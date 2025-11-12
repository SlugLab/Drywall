/*
 * CXL Proof Verifier eBPF Coprocessor with Firewall
 *
 * This eBPF program runs as a coprocessor inside the CXL Type 1 device
 * with dual functionality:
 *
 * 1. FIREWALL: Filter and control access to crypto metadata regions
 *    - Block unauthorized devices from accessing LUKS headers, keys, IVs
 *    - Enforce per-device access policies
 *    - Rate limiting and anomaly detection
 *
 * 2. VERIFIER: Generate and validate proofs for program execution
 *    - Generate proof when device updates shadowed cacheline
 *    - Validate that crypto operations follow expected execution paths
 *    - Verify program correctness (e.g., IV incremented correctly)
 *    - Detect malicious or buggy device behavior
 *
 * Proof includes:
 * - Hash of original shadow data
 * - Hash of new data
 * - Execution trace checksum (program path verification)
 * - Timestamp and sequence number
 * - Device signature (HMAC)
 *
 * Copyright (c) 2025 Drywall Project
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * Build:
 * clang -O2 -target bpf -D__TARGET_ARCH_x86_64 -g -Wall \
 *   -Wno-address-of-packed-member -Wno-missing-prototypes \
 *   -I/usr/include/x86_64-linux-gnu \
 *   -c tools/ebpf/cxl_proof_verifier.bpf.c \
 *   -o tools/ebpf/cxl_proof_verifier.bpf.o
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>

/* Access decision from firewall */
enum firewall_action {
    FW_ALLOW = 0,               /* Allow access */
    FW_DENY = 1,                /* Deny access */
    FW_RATE_LIMIT = 2,          /* Rate limited - deny temporarily */
    FW_QUARANTINE = 3,          /* Device quarantined - permanent deny */
};

/* Firewall rule */
struct firewall_rule {
    __u64 addr_start;           /* Address range start */
    __u64 addr_end;             /* Address range end */
    __u32 region_type;          /* Crypto region type */
    __u32 allowed_devices[8];   /* Bitmap of allowed device IDs (256 devices) */
    __u32 max_access_rate;      /* Max accesses per second */
    __u8 deny_write;            /* Deny write access? */
    __u8 deny_read;             /* Deny read access? */
    __u8 enabled;               /* Rule enabled? */
    __u8 padding;
} __attribute__((packed));

/* Execution trace for program verification */
struct execution_trace {
    __u64 trace_id;             /* Unique trace identifier */
    __u32 operation_type;       /* Crypto operation type */
    __u32 step_count;           /* Number of execution steps */
    __u64 checksum;             /* Checksum of execution path */
    __u64 expected_outcome_hash;/* Expected result hash */
} __attribute__((packed));

/* Proof structure (extended with execution trace) */
struct crypto_proof {
    __u64 timestamp;            /* When proof was generated */
    __u64 sequence;             /* Monotonic sequence number */
    __u64 shadow_hash;          /* Hash of original shadow data */
    __u64 new_hash;             /* Hash of new data */
    __u64 addr;                 /* Cacheline address */
    __u32 device_id;            /* Device that made the update */
    __u32 operation_type;       /* Type of crypto operation */

    /* Program execution verification */
    __u64 exec_trace_checksum;  /* Execution path checksum */
    __u32 exec_step_count;      /* Steps in execution */
    __u32 exec_flags;           /* Execution flags */

    __u8 hmac[32];              /* HMAC signature */
    __u8 padding[8];            /* Pad to 128 bytes */
} __attribute__((packed));

/* Shadow entry metadata */
struct shadow_metadata {
    __u64 addr;
    __u64 epoch;                /* Creation time */
    __u64 sequence;             /* Current sequence number */
    __u32 device_id;
    __u32 region_type;
    __u8 shadow_data[64];       /* Original shadow data */
    __u64 shadow_hash;
} __attribute__((packed));

/* Proof validation result */
enum proof_result {
    PROOF_VALID = 0,
    PROOF_INVALID_HMAC = 1,
    PROOF_INVALID_SEQUENCE = 2,
    PROOF_INVALID_HASH = 3,
    PROOF_INVALID_EXECUTION = 4,
    PROOF_TIMEOUT = 5,
};

/* Device key for HMAC */
struct device_key {
    __u32 device_id;
    __u8 key[32];
} __attribute__((packed));

/* Statistics */
struct stats_entry {
    __u64 total_accesses;
    __u64 firewall_allows;
    __u64 firewall_denies;
    __u64 firewall_rate_limits;
    __u64 firewall_quarantine_blocks;
    __u64 proofs_generated;
    __u64 proofs_validated;
    __u64 proofs_failed;
    __u64 exec_verifications;
    __u64 exec_iv_violations;
    __u64 exec_path_violations;
} __attribute__((packed));

/*
 * BPF MAPS
 */

/* Map 1: Firewall rules (max 256 rules) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);           /* rule_id */
    __type(value, struct firewall_rule);
} firewall_rules_map SEC(".maps");

/* Map 2: Device access counters (for rate limiting) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);           /* device_id */
    __type(value, __u64);         /* access_count */
} device_access_count_map SEC(".maps");

/* Map 3: Quarantine bitmap (256 devices) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);       /* 8 * 32-bit = 256 devices */
    __type(key, __u32);           /* bitmap_index (0-7) */
    __type(value, __u32);         /* bitmap_value */
} quarantine_bitmap_map SEC(".maps");

/* Map 4: Execution traces for verification */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);           /* trace_id */
    __type(value, struct execution_trace);
} exec_trace_map SEC(".maps");

/* Map 5: Shadow metadata */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);           /* cacheline addr */
    __type(value, struct shadow_metadata);
} shadow_metadata_map SEC(".maps");

/* Map 6: Device HMAC keys */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);           /* device_id */
    __type(value, struct device_key);
} device_keys_map SEC(".maps");

/* Map 7: Proof validation cache */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);           /* proof hash */
    __type(value, __u32);         /* validation_result */
} validation_cache_map SEC(".maps");

/* Map 8: Statistics */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_entry);
} stats_map SEC(".maps");

/* Map 9: Proof event ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256KB ring buffer */
} proof_events SEC(".maps");

/*
 * HELPER FUNCTIONS
 */

static __always_inline __u64 get_timestamp(void)
{
    return bpf_ktime_get_ns();
}

static __always_inline int is_device_quarantined(__u32 device_id)
{
    __u32 bitmap_idx = device_id / 32;
    __u32 bit_pos = device_id % 32;
    __u32 *bitmap;

    if (bitmap_idx >= 8)
        return 0;

    bitmap = bpf_map_lookup_elem(&quarantine_bitmap_map, &bitmap_idx);
    if (!bitmap)
        return 0;

    return (*bitmap & (1U << bit_pos)) != 0;
}

static __always_inline void set_device_quarantined(__u32 device_id)
{
    __u32 bitmap_idx = device_id / 32;
    __u32 bit_pos = device_id % 32;
    __u32 *bitmap;

    if (bitmap_idx >= 8)
        return;

    bitmap = bpf_map_lookup_elem(&quarantine_bitmap_map, &bitmap_idx);
    if (bitmap) {
        __u32 new_val = *bitmap | (1U << bit_pos);
        bpf_map_update_elem(&quarantine_bitmap_map, &bitmap_idx, &new_val, BPF_ANY);
    }
}

static __always_inline int is_device_allowed(struct firewall_rule *rule, __u32 device_id)
{
    __u32 bitmap_idx = device_id / 32;
    __u32 bit_pos = device_id % 32;

    if (bitmap_idx >= 8)
        return 0;

    return (rule->allowed_devices[bitmap_idx] & (1U << bit_pos)) != 0;
}

/* Simple hash function for small data */
static __always_inline __u64 compute_hash(const __u8 *data, __u32 len)
{
    __u64 hash = 0xcbf29ce484222325ULL;  /* FNV-1a offset basis */
    __u32 i;

    #pragma unroll
    for (i = 0; i < 64 && i < len; i++) {
        hash ^= data[i];
        hash *= 0x100000001b3ULL;  /* FNV-1a prime */
    }

    return hash;
}

/* Simple HMAC (for demonstration - real hardware would use crypto engine) */
static __always_inline void compute_hmac(const __u8 *data, __u32 len,
                                          const __u8 *key, __u8 *out)
{
    __u64 h1 = compute_hash(data, len);
    __u64 h2 = compute_hash(key, 32);
    __u64 hmac = h1 ^ h2;

    #pragma unroll
    for (int i = 0; i < 32; i++) {
        out[i] = (__u8)((hmac >> (i % 8)) & 0xFF);
    }
}

static __always_inline struct stats_entry *get_stats(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&stats_map, &key);
}

/*
 * FIREWALL PROGRAMS
 */

/* Input context for firewall check */
struct firewall_ctx {
    __u64 addr;
    __u32 device_id;
    __u8 is_write;
    __u8 padding[3];
};

/*
 * Firewall check - called before granting exclusive access
 */
SEC("syscall")
int cxl_firewall_check(struct firewall_ctx *ctx)
{
    __u64 addr = ctx->addr;
    __u32 device_id = ctx->device_id;
    __u8 is_write = ctx->is_write;
    struct stats_entry *stats;
    __u32 rule_id;

    stats = get_stats();
    if (stats) {
        __sync_fetch_and_add(&stats->total_accesses, 1);
    }

    /* Check 1: Device quarantined? */
    if (is_device_quarantined(device_id)) {
        if (stats)
            __sync_fetch_and_add(&stats->firewall_quarantine_blocks, 1);
        return FW_QUARANTINE;
    }

    /* Check 2: Rate limiting */
    __u64 *access_count = bpf_map_lookup_elem(&device_access_count_map, &device_id);
    if (access_count) {
        if ((*access_count) > 1000) {  /* Max 1000 accesses per second */
            if (stats)
                __sync_fetch_and_add(&stats->firewall_rate_limits, 1);
            return FW_RATE_LIMIT;
        }
        __sync_fetch_and_add(access_count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&device_access_count_map, &device_id, &initial, BPF_NOEXIST);
    }

    /* Check 3: Firewall rules
     * NOTE: In real hardware, this would check all 256 rules.
     * For kernel loading, we limit to 32 rules to satisfy the verifier.
     */
    #pragma unroll
    for (rule_id = 0; rule_id < 32; rule_id++) {
        struct firewall_rule *rule = bpf_map_lookup_elem(&firewall_rules_map, &rule_id);
        if (!rule || !rule->enabled)
            continue;

        /* Check if address is in range */
        if (addr >= rule->addr_start && addr <= rule->addr_end) {
            /* Check device allowed */
            if (!is_device_allowed(rule, device_id)) {
                if (stats)
                    __sync_fetch_and_add(&stats->firewall_denies, 1);
                return FW_DENY;
            }

            /* Check read/write permissions */
            if (is_write && rule->deny_write) {
                if (stats)
                    __sync_fetch_and_add(&stats->firewall_denies, 1);
                return FW_DENY;
            }
            if (!is_write && rule->deny_read) {
                if (stats)
                    __sync_fetch_and_add(&stats->firewall_denies, 1);
                return FW_DENY;
            }
        }
    }

    /* Default: ALLOW */
    if (stats)
        __sync_fetch_and_add(&stats->firewall_allows, 1);
    return FW_ALLOW;
}

/*
 * VERIFIER PROGRAMS
 */

/* Input context for execution verification */
struct exec_verify_ctx {
    __u64 trace_id;
    __u32 operation_type;
    __u8 old_data[64];
    __u8 new_data[64];
};

/*
 * Verify program execution correctness
 */
SEC("syscall")
int cxl_verify_execution(struct exec_verify_ctx *ctx)
{
    __u64 trace_id = ctx->trace_id;
    __u32 operation_type = ctx->operation_type;
    struct execution_trace *trace;
    struct stats_entry *stats;

    stats = get_stats();
    if (stats)
        __sync_fetch_and_add(&stats->exec_verifications, 1);

    /* Lookup execution trace */
    trace = bpf_map_lookup_elem(&exec_trace_map, &trace_id);
    if (!trace)
        return -1;  /* No trace found */

    /* Verify operation type matches */
    if (trace->operation_type != operation_type)
        return -1;

    /* Verify expected outcome hash */
    __u64 actual_hash = compute_hash(ctx->new_data, 64);
    if (trace->expected_outcome_hash != actual_hash)
        return -1;

    /* Example: Verify IV increment for IV counter updates */
    if (operation_type == 1) {  /* IV_UPDATE */
        __u64 old_iv = 0, new_iv = 0;

        #pragma unroll
        for (__u32 i = 0; i < 8; i++) {
            old_iv |= (__u64)ctx->old_data[i] << (i * 8);
            new_iv |= (__u64)ctx->new_data[i] << (i * 8);
        }

        if (new_iv <= old_iv) {
            /* IV not incremented - violation! */
            if (stats)
                __sync_fetch_and_add(&stats->exec_iv_violations, 1);
            return -1;
        }
    }

    return 0;  /* Verification passed */
}

/*
 * PROOF GENERATION AND VALIDATION
 */

/* Input context for proof generation */
struct proof_gen_ctx {
    __u64 addr;
    __u32 device_id;
    __u8 old_data[64];
    __u8 new_data[64];
    __u64 trace_id;
};

/*
 * Generate cryptographic proof of update
 */
SEC("syscall")
int cxl_generate_proof(struct proof_gen_ctx *ctx)
{
    struct crypto_proof *proof;
    struct shadow_metadata *shadow;
    struct device_key *device_key;
    struct execution_trace *exec_trace = NULL;
    struct stats_entry *stats;
    __u64 addr = ctx->addr;
    __u32 device_id = ctx->device_id;
    __u64 trace_id = ctx->trace_id;

    stats = get_stats();

    /* Lookup shadow metadata */
    shadow = bpf_map_lookup_elem(&shadow_metadata_map, &addr);
    if (!shadow)
        return -1;

    /* Lookup device key */
    device_key = bpf_map_lookup_elem(&device_keys_map, &device_id);
    if (!device_key)
        return -1;

    /* Lookup execution trace (if provided) */
    if (trace_id != 0) {
        exec_trace = bpf_map_lookup_elem(&exec_trace_map, &trace_id);
    }

    /* Reserve space in ring buffer */
    proof = bpf_ringbuf_reserve(&proof_events, sizeof(*proof), 0);
    if (!proof)
        return -1;

    /* Fill proof structure */
    proof->timestamp = get_timestamp();
    proof->sequence = shadow->sequence + 1;
    proof->shadow_hash = compute_hash(ctx->old_data, 64);
    proof->new_hash = compute_hash(ctx->new_data, 64);
    proof->addr = addr;
    proof->device_id = device_id;
    proof->operation_type = exec_trace ? exec_trace->operation_type : 0;

    /* Add execution trace information */
    if (exec_trace) {
        proof->exec_trace_checksum = exec_trace->checksum;
        proof->exec_step_count = exec_trace->step_count;
        proof->exec_flags = 1;
    } else {
        proof->exec_trace_checksum = 0;
        proof->exec_step_count = 0;
        proof->exec_flags = 0;
    }

    /* Compute HMAC signature */
    compute_hmac((__u8 *)proof, sizeof(*proof) - 40, device_key->key, proof->hmac);

    /* Submit proof to ring buffer */
    bpf_ringbuf_submit(proof, 0);

    if (stats)
        __sync_fetch_and_add(&stats->proofs_generated, 1);

    return 0;
}

/* Input context for proof validation */
struct proof_validate_ctx {
    struct crypto_proof proof;
};

/*
 * Validate cryptographic proof
 */
SEC("syscall")
int cxl_validate_proof(struct proof_validate_ctx *ctx)
{
    struct crypto_proof *proof = &ctx->proof;
    struct shadow_metadata *shadow;
    struct device_key *device_key;
    struct stats_entry *stats;
    __u8 computed_hmac[32];
    __u32 i;

    stats = get_stats();

    /* Lookup shadow metadata */
    shadow = bpf_map_lookup_elem(&shadow_metadata_map, &proof->addr);
    if (!shadow) {
        if (stats)
            __sync_fetch_and_add(&stats->proofs_failed, 1);
        return PROOF_INVALID_HASH;
    }

    /* Validate sequence number */
    if (proof->sequence != shadow->sequence + 1) {
        if (stats)
            __sync_fetch_and_add(&stats->proofs_failed, 1);
        return PROOF_INVALID_SEQUENCE;
    }

    /* Validate shadow hash */
    if (proof->shadow_hash != shadow->shadow_hash) {
        if (stats)
            __sync_fetch_and_add(&stats->proofs_failed, 1);
        return PROOF_INVALID_HASH;
    }

    /* Lookup device key */
    device_key = bpf_map_lookup_elem(&device_keys_map, &proof->device_id);
    if (!device_key) {
        if (stats)
            __sync_fetch_and_add(&stats->proofs_failed, 1);
        return PROOF_INVALID_HMAC;
    }

    /* Verify HMAC */
    compute_hmac((__u8 *)proof, sizeof(*proof) - 40, device_key->key, computed_hmac);

    #pragma unroll
    for (i = 0; i < 32; i++) {
        if (computed_hmac[i] != proof->hmac[i]) {
            if (stats)
                __sync_fetch_and_add(&stats->proofs_failed, 1);
            return PROOF_INVALID_HMAC;
        }
    }

    /* Validate execution trace if present */
    if (proof->exec_flags & 1) {
        struct execution_trace *trace = bpf_map_lookup_elem(&exec_trace_map, &proof->addr);
        if (trace && trace->checksum != proof->exec_trace_checksum) {
            if (stats)
                __sync_fetch_and_add(&stats->proofs_failed, 1);
            return PROOF_INVALID_EXECUTION;
        }
    }

    if (stats)
        __sync_fetch_and_add(&stats->proofs_validated, 1);

    return PROOF_VALID;
}

/*
 * SHADOW MANAGEMENT
 */

/* Input context for shadow registration */
struct shadow_register_ctx {
    __u64 addr;
    __u32 device_id;
    __u32 region_type;
    __u8 data[64];
};

/*
 * Register new shadow metadata
 */
SEC("syscall")
int cxl_register_shadow(struct shadow_register_ctx *ctx)
{
    struct shadow_metadata shadow = {};

    shadow.addr = ctx->addr;
    shadow.epoch = get_timestamp();
    shadow.sequence = 0;
    shadow.device_id = ctx->device_id;
    shadow.region_type = ctx->region_type;

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        shadow.shadow_data[i] = ctx->data[i];
    }

    shadow.shadow_hash = compute_hash(ctx->data, 64);

    bpf_map_update_elem(&shadow_metadata_map, &ctx->addr, &shadow, BPF_ANY);

    return 0;
}

/*
 * Unregister shadow metadata
 */
SEC("syscall")
int cxl_unregister_shadow(struct shadow_register_ctx *ctx)
{
    bpf_map_delete_elem(&shadow_metadata_map, &ctx->addr);
    return 0;
}

/*
 * Set device HMAC key
 */
SEC("syscall")
int cxl_set_device_key(struct device_key *key)
{
    bpf_map_update_elem(&device_keys_map, &key->device_id, key, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
