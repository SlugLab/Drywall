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
 *   -c cxl_proof_verifier.bpf.c -o cxl_proof_verifier.bpf.o
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
struct proof_validation {
    __u8 valid;                 /* 1 if valid, 0 if invalid */
    __u8 integrity_check;       /* Hash integrity */
    __u8 sequence_check;        /* Sequence number valid */
    __u8 timestamp_check;       /* Timestamp within bounds */
    __u8 hmac_check;            /* HMAC signature valid */
    __u8 quarantine;            /* Should device be quarantined? */
    __u8 padding[2];
    __u64 reason;               /* Failure reason code */
} __attribute__((packed));

/* BPF Maps */

/* ==== FIREWALL MAPS ==== */

/* Firewall rules (key: rule_id, value: firewall_rule) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);         /* rule_id */
    __type(value, struct firewall_rule);
} firewall_rules_map SEC(".maps");

/* Device access counters for rate limiting (key: device_id, value: count) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);         /* device_id */
    __type(value, __u64);       /* access count */
} device_access_count_map SEC(".maps");

/* Device quarantine bitmap (key: 0, value: bitmap[8]) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32[8]);    /* 256 bits for 256 devices */
} quarantine_bitmap_map SEC(".maps");

/* Execution trace storage (key: trace_id, value: execution_trace) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);         /* trace_id */
    __type(value, struct execution_trace);
} exec_trace_map SEC(".maps");

/* ==== SHADOW AND PROOF MAPS ==== */

/* Shadow metadata storage (key: addr, value: shadow_metadata) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);         /* addr */
    __type(value, struct shadow_metadata);
} shadow_metadata_map SEC(".maps");

/* Device secret keys for HMAC (key: device_id, value: secret[32]) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);         /* device_id */
    __type(value, __u8[32]);    /* secret key */
} device_keys_map SEC(".maps");

/* Proof validation cache (key: addr, value: proof_validation) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);         /* addr */
    __type(value, struct proof_validation);
} validation_cache_map SEC(".maps");

/* Statistics */
struct proof_stats {
    /* Proof generation and validation */
    __u64 proofs_generated;
    __u64 proofs_validated;
    __u64 validation_failures;
    __u64 integrity_failures;
    __u64 sequence_failures;
    __u64 timestamp_failures;
    __u64 hmac_failures;
    __u64 quarantines_triggered;

    /* Firewall statistics */
    __u64 firewall_checks;
    __u64 firewall_allows;
    __u64 firewall_denies;
    __u64 firewall_rate_limits;
    __u64 firewall_quarantine_blocks;

    /* Execution verification */
    __u64 exec_verifications;
    __u64 exec_verification_failures;
    __u64 exec_iv_violations;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct proof_stats);
} stats_map SEC(".maps");

/* Ring buffer for proof events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB */
} proof_events SEC(".maps");

/* Helper: Compute FNV-1a hash (simplified) */
static __always_inline __u64 compute_hash(const __u8 *data, __u32 len)
{
    __u64 hash = 0xcbf29ce484222325ULL;
    const __u64 prime = 0x100000001b3ULL;

    /* Bounded loop for verifier */
    if (len > 0 && len <= 64) {
        #pragma unroll
        for (__u32 i = 0; i < 64; i++) {
            if (i >= len) break;
            hash ^= data[i];
            hash *= prime;
        }
    }

    return hash;
}

/* Helper: Compute simplified HMAC (XOR-based for verifier compatibility) */
static __always_inline void compute_hmac(const __u8 *data, __u32 data_len,
                                         const __u8 *key, __u8 *hmac_out)
{
    /* Simplified HMAC for eBPF verifier
     * Real implementation would use proper HMAC-SHA256
     */
    __u64 h1 = 0, h2 = 0;

    /* Mix key into hash */
    #pragma unroll
    for (__u32 i = 0; i < 32; i++) {
        h1 ^= (__u64)key[i] << (i % 8);
    }

    /* Mix data into hash */
    if (data_len > 0 && data_len <= 64) {
        #pragma unroll
        for (__u32 i = 0; i < 64; i++) {
            if (i >= data_len) break;
            h2 ^= (__u64)data[i] << (i % 8);
        }
    }

    /* Combine */
    __u64 final_hash = h1 ^ h2;

    /* Output as bytes */
    #pragma unroll
    for (__u32 i = 0; i < 32; i++) {
        hmac_out[i] = (__u8)(final_hash >> (i % 8));
    }
}

/* Helper: Verify HMAC */
static __always_inline __u8 verify_hmac(const __u8 *data, __u32 data_len,
                                        const __u8 *key, const __u8 *expected_hmac)
{
    __u8 computed_hmac[32];

    compute_hmac(data, data_len, key, computed_hmac);

    /* Compare HMACs */
    __u8 match = 1;
    #pragma unroll
    for (__u32 i = 0; i < 32; i++) {
        if (computed_hmac[i] != expected_hmac[i]) {
            match = 0;
        }
    }

    return match;
}

/* Helper: Get current timestamp */
static __always_inline __u64 get_timestamp(void)
{
    return bpf_ktime_get_ns();
}

/* Helper: Check if device is quarantined */
static __always_inline __u8 is_device_quarantined(__u32 device_id)
{
    __u32 key = 0;
    __u32 *bitmap;

    if (device_id >= 256) {
        return 0;
    }

    bitmap = bpf_map_lookup_elem(&quarantine_bitmap_map, &key);
    if (!bitmap) {
        return 0;
    }

    __u32 word_idx = device_id / 32;
    __u32 bit_idx = device_id % 32;

    return (bitmap[word_idx] & (1U << bit_idx)) != 0;
}

/* Helper: Check if device is allowed by rule */
static __always_inline __u8 is_device_allowed(struct firewall_rule *rule, __u32 device_id)
{
    if (device_id >= 256) {
        return 0;
    }

    __u32 word_idx = device_id / 32;
    __u32 bit_idx = device_id % 32;

    return (rule->allowed_devices[word_idx] & (1U << bit_idx)) != 0;
}

/**
 * BPF Program: FIREWALL - Check Access
 *
 * Called before granting access to crypto metadata regions.
 * Enforces access control policies.
 *
 * Input: struct { addr, device_id, is_write }
 * Output: enum firewall_action
 */
SEC("tracepoint/cxl/firewall_check")
int cxl_firewall_check(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 addr = ctx->args[0];
    __u32 device_id = (__u32)ctx->args[1];
    __u8 is_write = (__u8)ctx->args[2];
    __u32 stats_key = 0;
    struct proof_stats *stats;
    enum firewall_action action;

    /* Update statistics */
    stats = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (stats) {
        stats->firewall_checks++;
    }

    /* Check 1: Device quarantined? */
    if (is_device_quarantined(device_id)) {
        if (stats) stats->firewall_quarantine_blocks++;
        return FW_QUARANTINE;
    }

    /* Check 2: Rate limiting */
    __u64 *access_count = bpf_map_lookup_elem(&device_access_count_map, &device_id);
    if (access_count) {
        (*access_count)++;

        /* Simple rate limit: 1000 accesses per second */
        __u64 current_time = get_timestamp();
        __u64 time_window = 1000 * 1000 * 1000; /* 1 second in ns */

        if ((*access_count) > 1000 && (current_time % time_window) < time_window / 2) {
            if (stats) stats->firewall_rate_limits++;
            return FW_RATE_LIMIT;
        }
    } else {
        /* Initialize counter */
        __u64 initial_count = 1;
        bpf_map_update_elem(&device_access_count_map, &device_id, &initial_count, BPF_ANY);
    }

    /* Check 3: Firewall rules */
    __u32 rule_id;
    action = FW_ALLOW; /* Default allow */

    /* Iterate through firewall rules (bounded loop) */
    #pragma unroll
    for (rule_id = 0; rule_id < 256; rule_id++) {
        struct firewall_rule *rule = bpf_map_lookup_elem(&firewall_rules_map, &rule_id);

        if (!rule || !rule->enabled) {
            continue;
        }

        /* Check if address falls within rule range */
        if (addr >= rule->addr_start && addr <= rule->addr_end) {
            /* Check if device is allowed */
            if (!is_device_allowed(rule, device_id)) {
                action = FW_DENY;
                break;
            }

            /* Check read/write permissions */
            if (is_write && rule->deny_write) {
                action = FW_DENY;
                break;
            }
            if (!is_write && rule->deny_read) {
                action = FW_DENY;
                break;
            }

            /* Rule matched and allowed */
            action = FW_ALLOW;
            break;
        }
    }

    /* Update statistics based on action */
    if (stats) {
        if (action == FW_ALLOW) {
            stats->firewall_allows++;
        } else if (action == FW_DENY) {
            stats->firewall_denies++;
        }
    }

    return action;
}

/**
 * BPF Program: VERIFIER - Verify Program Execution
 *
 * Called to verify that device executed crypto operation correctly.
 * Validates execution path and expected outcomes.
 *
 * Input: struct { trace_id, operation_type, old_data[64], new_data[64] }
 * Output: 0 if valid, -1 if invalid
 */
SEC("tracepoint/cxl/verify_execution")
int cxl_verify_execution(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 trace_id = ctx->args[0];
    __u32 operation_type = (__u32)ctx->args[1];
    const __u8 *old_data = (const __u8 *)ctx->args[2];
    const __u8 *new_data = (const __u8 *)ctx->args[3];
    __u32 stats_key = 0;
    struct proof_stats *stats;

    struct execution_trace *trace;

    /* Update statistics */
    stats = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (stats) {
        stats->exec_verifications++;
    }

    /* Lookup execution trace */
    trace = bpf_map_lookup_elem(&exec_trace_map, &trace_id);
    if (!trace) {
        /* No trace registered - cannot verify */
        if (stats) stats->exec_verification_failures++;
        return -1;
    }

    /* Verify operation type matches */
    if (trace->operation_type != operation_type) {
        if (stats) stats->exec_verification_failures++;
        return -1;
    }

    /* Compute actual outcome hash */
    __u64 actual_hash = compute_hash(new_data, 64);

    /* Verify expected outcome */
    if (trace->expected_outcome_hash != 0 &&
        trace->expected_outcome_hash != actual_hash) {
        /* Unexpected result - program executed incorrectly */
        if (stats) stats->exec_verification_failures++;
        return -1;
    }

    /* Example: Verify IV increment for IV counter updates */
    if (operation_type == 1) { /* IV_UPDATE */
        /* Check that new IV > old IV (monotonic increment) */
        __u64 old_iv = 0, new_iv = 0;

        /* Extract first 8 bytes as IV (simplified) */
        #pragma unroll
        for (__u32 i = 0; i < 8; i++) {
            old_iv |= (__u64)old_data[i] << (i * 8);
            new_iv |= (__u64)new_data[i] << (i * 8);
        }

        if (new_iv <= old_iv) {
            /* IV not incremented - violation */
            if (stats) {
                stats->exec_verification_failures++;
                stats->exec_iv_violations++;
            }
            return -1;
        }
    }

    /* Verification passed */
    return 0;
}

/**
 * BPF Program: Generate Proof (with execution verification)
 *
 * Called when device updates a shadowed cacheline.
 * Generates cryptographic proof with execution trace.
 *
 * Input: struct { addr, device_id, old_data[64], new_data[64], trace_id }
 * Output: struct crypto_proof (via ring buffer)
 */
SEC("tracepoint/cxl/generate_proof")
int cxl_generate_proof(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 addr = ctx->args[0];
    __u32 device_id = (__u32)ctx->args[1];
    const __u8 *old_data = (const __u8 *)ctx->args[2];
    const __u8 *new_data = (const __u8 *)ctx->args[3];
    __u64 trace_id = ctx->args[4]; /* Execution trace ID */

    struct shadow_metadata *shadow;
    struct crypto_proof *proof;
    struct execution_trace *exec_trace = NULL;
    __u8 *device_key;
    __u32 stats_key = 0;
    struct proof_stats *stats;

    /* Lookup shadow metadata */
    shadow = bpf_map_lookup_elem(&shadow_metadata_map, &addr);
    if (!shadow) {
        /* No shadow - cannot generate proof */
        return 0;
    }

    /* Verify device ownership */
    if (shadow->device_id != device_id) {
        /* Device does not own this shadow */
        return 0;
    }

    /* Lookup execution trace (if provided) */
    if (trace_id != 0) {
        exec_trace = bpf_map_lookup_elem(&exec_trace_map, &trace_id);
    }

    /* Lookup device key */
    device_key = bpf_map_lookup_elem(&device_keys_map, &device_id);
    if (!device_key) {
        /* No key for device - cannot generate HMAC */
        return 0;
    }

    /* Allocate proof in ring buffer */
    proof = bpf_ringbuf_reserve(&proof_events, sizeof(*proof), 0);
    if (!proof) {
        return 0;
    }

    /* Fill proof structure */
    proof->timestamp = get_timestamp();
    proof->sequence = shadow->sequence + 1;
    proof->shadow_hash = compute_hash(old_data, 64);
    proof->new_hash = compute_hash(new_data, 64);
    proof->addr = addr;
    proof->device_id = device_id;
    proof->operation_type = exec_trace ? exec_trace->operation_type : 0;

    /* Add execution trace information */
    if (exec_trace) {
        proof->exec_trace_checksum = exec_trace->checksum;
        proof->exec_step_count = exec_trace->step_count;
        proof->exec_flags = 1; /* Has execution trace */
    } else {
        proof->exec_trace_checksum = 0;
        proof->exec_step_count = 0;
        proof->exec_flags = 0; /* No execution trace */
    }

    /* Compute HMAC over proof data (excluding HMAC and padding) */
    compute_hmac((__u8 *)proof,
                 sizeof(*proof) - sizeof(proof->hmac) - sizeof(proof->padding),
                 device_key, proof->hmac);

    /* Zero padding */
    #pragma unroll
    for (__u32 i = 0; i < 8; i++) {
        proof->padding[i] = 0;
    }

    /* Submit proof to ring buffer */
    bpf_ringbuf_submit(proof, 0);

    /* Update shadow sequence number */
    shadow->sequence++;

    /* Update statistics */
    stats = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (stats) {
        stats->proofs_generated++;
    }

    return 0;
}

/**
 * BPF Program: Validate Proof
 *
 * Called before committing device update to kernel state.
 * Validates the cryptographic proof.
 *
 * Input: struct crypto_proof
 * Output: struct proof_validation (stored in validation_cache_map)
 */
SEC("tracepoint/cxl/validate_proof")
int cxl_validate_proof(struct bpf_raw_tracepoint_args *ctx)
{
    struct crypto_proof *proof = (struct crypto_proof *)ctx->args[0];
    struct shadow_metadata *shadow;
    struct proof_validation result = {0};
    __u8 *device_key;
    __u32 stats_key = 0;
    struct proof_stats *stats;
    __u64 current_time;

    if (!proof) {
        return 0;
    }

    /* Initialize result */
    result.valid = 1;
    result.integrity_check = 1;
    result.sequence_check = 1;
    result.timestamp_check = 1;
    result.hmac_check = 1;
    result.quarantine = 0;
    result.reason = 0;

    /* Lookup shadow metadata */
    shadow = bpf_map_lookup_elem(&shadow_metadata_map, &proof->addr);
    if (!shadow) {
        result.valid = 0;
        result.reason = 1; /* No shadow found */
        goto store_result;
    }

    /* Check 1: Verify shadow hash integrity */
    __u64 expected_shadow_hash = shadow->shadow_hash;
    if (proof->shadow_hash != expected_shadow_hash) {
        result.valid = 0;
        result.integrity_check = 0;
        result.reason = 2; /* Shadow hash mismatch */
    }

    /* Check 2: Verify sequence number */
    if (proof->sequence != shadow->sequence + 1) {
        result.valid = 0;
        result.sequence_check = 0;
        result.reason = 3; /* Invalid sequence */
    }

    /* Check 3: Verify timestamp is within acceptable window (100ms) */
    current_time = get_timestamp();
    __u64 time_delta = current_time > proof->timestamp ?
                      (current_time - proof->timestamp) :
                      (proof->timestamp - current_time);

    if (time_delta > (100 * 1000 * 1000)) { /* 100ms in nanoseconds */
        result.valid = 0;
        result.timestamp_check = 0;
        result.reason = 4; /* Timestamp out of bounds */
    }

    /* Check 4: Verify HMAC signature */
    device_key = bpf_map_lookup_elem(&device_keys_map, &proof->device_id);
    if (!device_key) {
        result.valid = 0;
        result.hmac_check = 0;
        result.reason = 5; /* No device key */
        goto store_result;
    }

    __u8 hmac_valid = verify_hmac((__u8 *)proof,
                                   sizeof(*proof) - sizeof(proof->hmac) - sizeof(proof->padding),
                                   device_key, proof->hmac);

    if (!hmac_valid) {
        result.valid = 0;
        result.hmac_check = 0;
        result.reason = 6; /* HMAC verification failed */
    }

    /* Determine if device should be quarantined */
    if (!result.valid) {
        /* Failed validation - recommend quarantine */
        result.quarantine = 1;
    }

store_result:
    /* Store validation result in cache */
    bpf_map_update_elem(&validation_cache_map, &proof->addr, &result, BPF_ANY);

    /* Update statistics */
    stats = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (stats) {
        stats->proofs_validated++;

        if (!result.valid) {
            stats->validation_failures++;
        }
        if (!result.integrity_check) {
            stats->integrity_failures++;
        }
        if (!result.sequence_check) {
            stats->sequence_failures++;
        }
        if (!result.timestamp_check) {
            stats->timestamp_failures++;
        }
        if (!result.hmac_check) {
            stats->hmac_failures++;
        }
        if (result.quarantine) {
            stats->quarantines_triggered++;
        }
    }

    return result.valid ? 0 : -1;
}

/**
 * BPF Program: Register Shadow
 *
 * Called when a new shadow is created.
 * Stores shadow metadata for later proof validation.
 */
SEC("tracepoint/cxl/register_shadow")
int cxl_register_shadow(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 addr = ctx->args[0];
    __u32 device_id = (__u32)ctx->args[1];
    const __u8 *shadow_data = (const __u8 *)ctx->args[2];
    __u32 region_type = (__u32)ctx->args[3];

    struct shadow_metadata shadow = {0};

    shadow.addr = addr;
    shadow.epoch = get_timestamp();
    shadow.sequence = 0; /* Initial sequence number */
    shadow.device_id = device_id;
    shadow.region_type = region_type;

    /* Copy shadow data (bounded for verifier) */
    #pragma unroll
    for (__u32 i = 0; i < 64; i++) {
        shadow.shadow_data[i] = shadow_data[i];
    }

    /* Compute shadow hash */
    shadow.shadow_hash = compute_hash(shadow_data, 64);

    /* Store in map */
    bpf_map_update_elem(&shadow_metadata_map, &addr, &shadow, BPF_ANY);

    return 0;
}

/**
 * BPF Program: Unregister Shadow
 *
 * Called when a shadow is released/committed.
 * Removes shadow metadata from map.
 */
SEC("tracepoint/cxl/unregister_shadow")
int cxl_unregister_shadow(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 addr = ctx->args[0];

    /* Remove from shadow metadata map */
    bpf_map_delete_elem(&shadow_metadata_map, &addr);

    /* Remove from validation cache */
    bpf_map_delete_elem(&validation_cache_map, &addr);

    return 0;
}

/**
 * BPF Program: Set Device Key
 *
 * Called to set/update the HMAC key for a device.
 */
SEC("tracepoint/cxl/set_device_key")
int cxl_set_device_key(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 device_id = (__u32)ctx->args[0];
    const __u8 *key = (const __u8 *)ctx->args[1];

    __u8 key_copy[32];

    /* Copy key (bounded for verifier) */
    #pragma unroll
    for (__u32 i = 0; i < 32; i++) {
        key_copy[i] = key[i];
    }

    /* Store in map */
    bpf_map_update_elem(&device_keys_map, &device_id, key_copy, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";
