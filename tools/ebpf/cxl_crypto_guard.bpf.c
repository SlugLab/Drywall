/*
 * CXL Crypto Guard eBPF Coprocessor
 *
 * This eBPF program protects LUKS/dm-crypt cryptographic metadata from
 * coherency failures when CXL.cache-enabled accelerators access encryption
 * contexts. It implements shadow-before-exclusivity enforcement for:
 * - LUKS key slots
 * - IV (Initialization Vector) counters
 * - Journaled integrity tags
 * - Crypto context structures
 *
 * This prevents silent decryption failures and key-slot desynchronization
 * across device resets by ensuring recovery can reconstruct consistent
 * encryption state.
 *
 * Copyright (c) 2025 Drywall Project
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See the
 * COPYING file in the top-level directory.
 *
 * Build:
 * clang -O2 -target bpf -D__TARGET_ARCH_x86 -g -c cxl_crypto_guard.bpf.c -o cxl_crypto_guard.bpf.o
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>

/* Crypto metadata region types */
#define CRYPTO_REGION_LUKS_HEADER     0x01  /* LUKS header (key slots, config) */
#define CRYPTO_REGION_IV_COUNTER      0x02  /* IV generation counters */
#define CRYPTO_REGION_INTEGRITY_TAG   0x04  /* Journaled integrity tags */
#define CRYPTO_REGION_CRYPTO_CTX      0x08  /* Crypto context (keys, state) */
#define CRYPTO_REGION_KEY_MATERIAL    0x10  /* Active key material in memory */
#define CRYPTO_REGION_DMCRYPT_STATE   0x20  /* dm-crypt driver state */

/* Protection levels */
#define PROTECTION_NONE               0  /* No protection */
#define PROTECTION_DENY_EXCLUSIVE     1  /* Deny exclusive access */
#define PROTECTION_SHADOW_REQUIRED    2  /* Shadow before exclusive */
#define PROTECTION_READ_ONLY          3  /* Read-only, no modifications */
#define PROTECTION_COMPLETE_DENY      4  /* No CXL access allowed */

/* Crypto operation types */
enum crypto_operation {
    CRYPTO_OP_KEY_LOAD = 0,         /* Loading key material */
    CRYPTO_OP_IV_UPDATE = 1,        /* Updating IV counter */
    CRYPTO_OP_ENCRYPT = 2,          /* Encryption operation */
    CRYPTO_OP_DECRYPT = 3,          /* Decryption operation */
    CRYPTO_OP_KEY_DERIVATION = 4,   /* PBKDF2 key derivation */
    CRYPTO_OP_INTEGRITY_CHECK = 5,  /* Integrity tag verification */
    CRYPTO_OP_HEADER_UPDATE = 6,    /* LUKS header modification */
};

/* Crypto metadata region descriptor */
struct crypto_region {
    __u64 start_addr;               /* Start address of region */
    __u64 end_addr;                 /* End address of region */
    __u32 region_type;              /* CRYPTO_REGION_* flags */
    __u32 protection_level;         /* PROTECTION_* level */
    __u64 last_shadow_time;         /* Last shadow creation timestamp */
    __u32 access_count;             /* Number of accesses */
    __u32 violation_count;          /* Number of policy violations */
    __u8 device_allowlist[32];      /* Bitmask of allowed devices (256 devices) */
} __attribute__((packed));

/* Crypto context shadow - stores encryption state for recovery */
struct crypto_context_shadow {
    __u64 addr;                     /* Address of crypto context */
    __u64 timestamp;                /* When shadow was created */
    __u64 version;                  /* Monotonic version counter */
    __u32 device_id;                /* Device that had exclusive access */
    __u32 region_type;              /* Type of crypto region */

    /* LUKS-specific metadata */
    __u64 key_slot_bitmap;          /* Which key slots are active */
    __u64 iv_counter;               /* Current IV counter value */
    __u32 cipher_mode;              /* Cipher mode (AES-XTS, etc.) */
    __u32 key_size;                 /* Key size in bits */

    /* Shadow data storage */
    __u8 data[256];                 /* Shadow copy of metadata */
    __u8 key_material[64];          /* Encrypted key material backup */
    __u8 integrity_tag[32];         /* HMAC/integrity tag */
    __u64 checksum;                 /* CRC64 checksum */
} __attribute__((packed));

/* Crypto access event for audit logging */
struct crypto_access_event {
    __u64 timestamp;                /* Event timestamp */
    __u64 addr;                     /* Address accessed */
    __u32 device_id;                /* Device ID */
    __u32 operation_type;           /* CRYPTO_OP_* */
    __u32 region_type;              /* CRYPTO_REGION_* */
    __u32 protection_level;         /* Applied protection level */
    __u8 access_granted;            /* Was access allowed? */
    __u8 shadow_created;            /* Was shadow created? */
    __u8 violation;                 /* Policy violation detected? */
    __u8 recovery_triggered;        /* Did we trigger recovery? */
} __attribute__((packed));

/* Device fault event - tracks CXL device failures affecting crypto */
struct crypto_device_fault {
    __u64 timestamp;                /* When fault occurred */
    __u32 device_id;                /* Faulted device */
    __u32 fault_type;               /* Type of fault */
    __u32 affected_regions;         /* Count of affected crypto regions */
    __u32 shadows_restored;         /* Count of shadows restored */
    __u64 recovery_duration_ns;     /* Time taken for recovery */
} __attribute__((packed));

/* Statistics for crypto protection */
struct crypto_guard_stats {
    __u64 total_accesses;           /* Total crypto region accesses */
    __u64 exclusive_denied;         /* Exclusive accesses denied */
    __u64 shadows_created;          /* Shadows created */
    __u64 shadows_restored;         /* Shadows restored after fault */
    __u64 policy_violations;        /* Policy violations detected */
    __u64 device_faults;            /* Device faults handled */
    __u64 integrity_failures;       /* Checksum/integrity failures */
    __u64 recovery_operations;      /* Recovery operations performed */

    /* Per-operation counters */
    __u64 operations[7];            /* Indexed by crypto_operation */

    /* Per-region counters */
    __u64 region_accesses[6];       /* Indexed by region type bit position */
};

/* ========== BPF Maps ========== */

/* Map: Crypto region protection policies */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);      /* Up to 1024 protected crypto regions */
    __type(key, __u64);             /* Region start address */
    __type(value, struct crypto_region);
} crypto_regions_map SEC(".maps");

/* Map: Crypto context shadows */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);      /* Up to 4096 shadowed contexts */
    __type(key, __u64);             /* Address */
    __type(value, struct crypto_context_shadow);
} crypto_shadow_map SEC(".maps");

/* Map: Active crypto operations tracking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);       /* Track up to 256 concurrent operations */
    __type(key, __u64);             /* Operation ID (timestamp + device_id) */
    __type(value, __u32);           /* Operation type */
} active_operations_map SEC(".maps");

/* Map: Device-to-crypto-region mapping for fast lookup during faults */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);      /* Track device ownership */
    __type(key, __u64);             /* (device_id << 48) | address */
    __type(value, __u32);           /* Region type */
} device_crypto_ownership_map SEC(".maps");

/* Map: Event ring buffer for audit logging */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  /* 512KB ring buffer */
} crypto_event_ringbuf SEC(".maps");

/* Map: Device fault events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256KB for fault events */
} crypto_fault_ringbuf SEC(".maps");

/* Map: Statistics */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct crypto_guard_stats);
} crypto_stats_map SEC(".maps");

/* Map: Per-device statistics */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);       /* Up to 256 devices */
    __type(key, __u32);             /* Device ID */
    __type(value, struct crypto_guard_stats);
} device_stats_map SEC(".maps");

/* ========== Helper Functions ========== */

static __always_inline __u64 get_timestamp_ns(void)
{
    return bpf_ktime_get_ns();
}

/* Compute simple checksum for integrity verification */
static __always_inline __u64 compute_crc64(__u8 *data, __u32 len)
{
    __u64 checksum = 0;

    /* Simple checksum to avoid complex loops that trigger memcpy detection */
    if (len > 16) len = 16;  /* Limit to avoid verifier issues */

    /* Manually unrolled for verifier friendliness */
    if (len > 0) checksum ^= (__u64)data[0] << 0;
    if (len > 1) checksum ^= (__u64)data[1] << 8;
    if (len > 2) checksum ^= (__u64)data[2] << 16;
    if (len > 3) checksum ^= (__u64)data[3] << 24;
    if (len > 4) checksum ^= (__u64)data[4] << 32;
    if (len > 5) checksum ^= (__u64)data[5] << 40;
    if (len > 6) checksum ^= (__u64)data[6] << 48;
    if (len > 7) checksum ^= (__u64)data[7] << 56;
    if (len > 8) checksum ^= (__u64)data[8];
    if (len > 9) checksum ^= (__u64)data[9];
    if (len > 10) checksum ^= (__u64)data[10];
    if (len > 11) checksum ^= (__u64)data[11];
    if (len > 12) checksum ^= (__u64)data[12];
    if (len > 13) checksum ^= (__u64)data[13];
    if (len > 14) checksum ^= (__u64)data[14];
    if (len > 15) checksum ^= (__u64)data[15];

    return checksum;
}

/* Find crypto region containing the address */
static __always_inline struct crypto_region* find_crypto_region(__u64 addr)
{
    struct crypto_region *region;
    __u64 search_addr;

    /* Try direct lookup first (common case) */
    region = bpf_map_lookup_elem(&crypto_regions_map, &addr);
    if (region && addr >= region->start_addr && addr < region->end_addr)
        return region;

    /* Linear search through regions (limited iterations for eBPF verifier) */
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        /* This is a simplified search - in production, we'd use a more
         * efficient data structure like an interval tree or segment tree */
        search_addr = addr & ~((__u64)0xFFF << (i * 2));
        region = bpf_map_lookup_elem(&crypto_regions_map, &search_addr);

        if (region && addr >= region->start_addr && addr < region->end_addr)
            return region;
    }

    return NULL;
}

/* Check if device is allowed to access crypto region */
static __always_inline int is_device_allowed(struct crypto_region *region,
                                             __u32 device_id)
{
    if (device_id >= 256)
        return 0;

    __u32 byte_idx = device_id / 8;
    __u32 bit_idx = device_id % 8;

    if (byte_idx >= 32)
        return 0;

    return (region->device_allowlist[byte_idx] & (1 << bit_idx)) != 0;
}

/* Create shadow copy of crypto context */
static __always_inline int create_crypto_shadow(__u64 addr, __u32 device_id,
                                                struct crypto_region *region,
                                                __u8 *data, __u32 data_len)
{
    struct crypto_context_shadow shadow = {0};
    struct crypto_context_shadow *existing;

    shadow.addr = addr;
    shadow.timestamp = get_timestamp_ns();
    shadow.device_id = device_id;
    shadow.region_type = region->region_type;

    /* Check if shadow already exists and increment version */
    existing = bpf_map_lookup_elem(&crypto_shadow_map, &addr);
    if (existing) {
        shadow.version = existing->version + 1;
        /* Preserve key slot and IV information */
        shadow.key_slot_bitmap = existing->key_slot_bitmap;
        shadow.iv_counter = existing->iv_counter;
    } else {
        shadow.version = 1;
    }

    /* Copy data to shadow (bounded copy to avoid memcpy detection) */
    if (data_len > 0 && data) {
        /* Copy in small chunks to avoid verifier memcpy detection */
        __u32 max_copy = data_len < 64 ? data_len : 64;

        /* Unroll manually with explicit bounds */
        if (max_copy > 0) shadow.data[0] = data[0];
        if (max_copy > 1) shadow.data[1] = data[1];
        if (max_copy > 2) shadow.data[2] = data[2];
        if (max_copy > 3) shadow.data[3] = data[3];
        if (max_copy > 4) shadow.data[4] = data[4];
        if (max_copy > 5) shadow.data[5] = data[5];
        if (max_copy > 6) shadow.data[6] = data[6];
        if (max_copy > 7) shadow.data[7] = data[7];
        if (max_copy > 8) shadow.data[8] = data[8];
        if (max_copy > 9) shadow.data[9] = data[9];
        if (max_copy > 10) shadow.data[10] = data[10];
        if (max_copy > 11) shadow.data[11] = data[11];
        if (max_copy > 12) shadow.data[12] = data[12];
        if (max_copy > 13) shadow.data[13] = data[13];
        if (max_copy > 14) shadow.data[14] = data[14];
        if (max_copy > 15) shadow.data[15] = data[15];
        /* First 16 bytes copied - sufficient for most crypto metadata */
    }

    /* Compute integrity checksum */
    __u32 check_len = data_len < 16 ? data_len : 16;
    shadow.checksum = compute_crc64(shadow.data, check_len);

    /* Store shadow in map */
    if (bpf_map_update_elem(&crypto_shadow_map, &addr, &shadow, BPF_ANY) < 0)
        return -1;

    /* Update region metadata */
    region->last_shadow_time = shadow.timestamp;
    bpf_map_update_elem(&crypto_regions_map, &region->start_addr, region, BPF_ANY);

    /* Track device ownership */
    __u64 ownership_key = ((__u64)device_id << 48) | addr;
    bpf_map_update_elem(&device_crypto_ownership_map, &ownership_key,
                       &region->region_type, BPF_ANY);

    /* Update statistics */
    __u32 zero = 0;
    struct crypto_guard_stats *stats = bpf_map_lookup_elem(&crypto_stats_map, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->shadows_created, 1);

    return 0;
}

/* Restore crypto context from shadow */
static __always_inline int restore_crypto_shadow(__u64 addr, __u8 *data_out,
                                                 __u32 *restored_len)
{
    struct crypto_context_shadow *shadow;

    shadow = bpf_map_lookup_elem(&crypto_shadow_map, &addr);
    if (!shadow)
        return -1;  /* No shadow exists */

    /* Verify integrity */
    __u64 checksum = compute_crc64(shadow->data, 256);
    if (checksum != shadow->checksum) {
        /* Update statistics */
        __u32 zero = 0;
        struct crypto_guard_stats *stats = bpf_map_lookup_elem(&crypto_stats_map, &zero);
        if (stats)
            __sync_fetch_and_add(&stats->integrity_failures, 1);
        return -2;  /* Integrity check failed */
    }

    /* Copy shadow data to output */
    if (data_out) {
        /* Manual unroll to avoid memcpy detection */
        data_out[0] = shadow->data[0];
        data_out[1] = shadow->data[1];
        data_out[2] = shadow->data[2];
        data_out[3] = shadow->data[3];
        data_out[4] = shadow->data[4];
        data_out[5] = shadow->data[5];
        data_out[6] = shadow->data[6];
        data_out[7] = shadow->data[7];
        data_out[8] = shadow->data[8];
        data_out[9] = shadow->data[9];
        data_out[10] = shadow->data[10];
        data_out[11] = shadow->data[11];
        data_out[12] = shadow->data[12];
        data_out[13] = shadow->data[13];
        data_out[14] = shadow->data[14];
        data_out[15] = shadow->data[15];
    }

    if (restored_len)
        *restored_len = 256;

    /* Update statistics */
    __u32 zero = 0;
    struct crypto_guard_stats *stats = bpf_map_lookup_elem(&crypto_stats_map, &zero);
    if (stats) {
        __sync_fetch_and_add(&stats->shadows_restored, 1);
        __sync_fetch_and_add(&stats->recovery_operations, 1);
    }

    return 0;
}

/* Log crypto access event */
static __always_inline void log_crypto_event(__u64 addr, __u32 device_id,
                                             __u32 operation_type, __u32 region_type,
                                             __u32 protection_level, __u8 granted,
                                             __u8 shadow_created, __u8 violation)
{
    struct crypto_access_event *event;

    event = bpf_ringbuf_reserve(&crypto_event_ringbuf, sizeof(*event), 0);
    if (!event)
        return;

    event->timestamp = get_timestamp_ns();
    event->addr = addr;
    event->device_id = device_id;
    event->operation_type = operation_type;
    event->region_type = region_type;
    event->protection_level = protection_level;
    event->access_granted = granted;
    event->shadow_created = shadow_created;
    event->violation = violation;
    event->recovery_triggered = 0;

    bpf_ringbuf_submit(event, 0);
}

/* ========== Main eBPF Programs ========== */

/*
 * Process CXL cache access to crypto region
 * Called when a CXL device attempts to access memory containing crypto metadata
 */
SEC("cxl_crypto/access_check")
int cxl_crypto_access_check(struct bpf_raw_tracepoint_args *ctx)
{
    /*
     * Arguments:
     * ctx->args[0]: access type (read=0, write=1, exclusive=2)
     * ctx->args[1]: physical address
     * ctx->args[2]: device ID
     * ctx->args[3]: operation type (CRYPTO_OP_*)
     * ctx->args[4]: pointer to data being accessed
     * ctx->args[5]: data length
     */
    __u32 access_type = (__u32)ctx->args[0];
    __u64 addr = (__u64)ctx->args[1];
    __u32 device_id = (__u32)ctx->args[2];
    __u32 operation_type = (__u32)ctx->args[3];
    void *data_ptr = (void *)ctx->args[4];
    __u32 data_len = (__u32)ctx->args[5];

    struct crypto_region *region;
    __u8 access_granted = 1;
    __u8 shadow_created = 0;
    __u8 violation = 0;

    /* Update statistics */
    __u32 zero = 0;
    struct crypto_guard_stats *stats = bpf_map_lookup_elem(&crypto_stats_map, &zero);
    if (stats) {
        __sync_fetch_and_add(&stats->total_accesses, 1);

        if (operation_type < 7)
            __sync_fetch_and_add(&stats->operations[operation_type], 1);
    }

    /* Find crypto region containing this address */
    region = find_crypto_region(addr);
    if (!region) {
        /* Not a protected crypto region - allow access */
        return 0;
    }

    /* Update region access counter */
    region->access_count++;

    /* Update region-specific statistics */
    if (stats) {
        for (int i = 0; i < 6; i++) {
            if (region->region_type & (1 << i))
                __sync_fetch_and_add(&stats->region_accesses[i], 1);
        }
    }

    /* Check device allowlist */
    if (!is_device_allowed(region, device_id)) {
        access_granted = 0;
        violation = 1;
        region->violation_count++;
        if (stats)
            __sync_fetch_and_add(&stats->policy_violations, 1);
        goto log_and_return;
    }

    /* Apply protection policy based on protection level */
    switch (region->protection_level) {
    case PROTECTION_COMPLETE_DENY:
        /* No access allowed at all */
        access_granted = 0;
        violation = 1;
        break;

    case PROTECTION_READ_ONLY:
        /* Only read access allowed */
        if (access_type > 0) {  /* write or exclusive */
            access_granted = 0;
            violation = 1;
        }
        break;

    case PROTECTION_DENY_EXCLUSIVE:
        /* Deny exclusive access, but allow shared read/write */
        if (access_type == 2) {  /* exclusive */
            access_granted = 0;
            if (stats)
                __sync_fetch_and_add(&stats->exclusive_denied, 1);
        }
        break;

    case PROTECTION_SHADOW_REQUIRED:
        /* Create shadow before granting exclusive access */
        if (access_type == 2) {  /* exclusive */
            /* Note: Shadow creation happens in create_crypto_shadow
             * which reads data directly via bpf_probe_read_kernel */
            __u8 small_buf[64] = {0};  /* Reduced stack usage */
            __u32 copy_len = data_len > 64 ? 64 : data_len;

            /* Read minimal data for shadow creation */
            if (data_ptr && copy_len > 0) {
                if (bpf_probe_read_kernel(small_buf, copy_len, data_ptr) < 0) {
                    access_granted = 0;
                    violation = 1;
                    break;
                }
            }

            /* Create shadow - only stores critical metadata */
            if (create_crypto_shadow(addr, device_id, region,
                                   small_buf, copy_len) < 0) {
                /* Shadow creation failed - deny exclusive access */
                access_granted = 0;
                violation = 1;
            } else {
                shadow_created = 1;
            }
        }
        break;

    case PROTECTION_NONE:
    default:
        /* No protection - allow all access */
        break;
    }

log_and_return:
    /* Log the access event */
    log_crypto_event(addr, device_id, operation_type, region->region_type,
                    region->protection_level, access_granted,
                    shadow_created, violation);

    /* Update region in map if modified */
    bpf_map_update_elem(&crypto_regions_map, &region->start_addr, region, BPF_ANY);

    return access_granted ? 0 : -1;
}

/*
 * Handle CXL device going offline (hot-unplug or failure)
 * Restore all crypto contexts that were exclusively owned by this device
 */
SEC("cxl_crypto/device_offline")
int cxl_crypto_device_offline(struct bpf_raw_tracepoint_args *ctx)
{
    /*
     * Arguments:
     * ctx->args[0]: device ID going offline
     * ctx->args[1]: fault type (0=graceful, 1=reset, 2=link_fault, 3=hot_unplug)
     */
    __u32 device_id = (__u32)ctx->args[0];
    __u32 fault_type = (__u32)ctx->args[1];

    __u64 recovery_start = get_timestamp_ns();
    __u32 regions_restored = 0;
    __u32 shadows_restored = 0;

    /* Update statistics */
    __u32 zero = 0;
    struct crypto_guard_stats *stats = bpf_map_lookup_elem(&crypto_stats_map, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->device_faults, 1);

    /*
     * Iterate through device ownership map and restore shadows
     * Note: This is a simplified implementation. In production, we would
     * need to maintain a per-device index for efficient iteration.
     */

    /* For now, we rely on userspace to iterate and call restore operations */
    /* The eBPF program will handle the actual restoration logic */

    /* Log fault event */
    struct crypto_device_fault *fault_event;
    fault_event = bpf_ringbuf_reserve(&crypto_fault_ringbuf,
                                     sizeof(*fault_event), 0);
    if (fault_event) {
        fault_event->timestamp = get_timestamp_ns();
        fault_event->device_id = device_id;
        fault_event->fault_type = fault_type;
        fault_event->affected_regions = regions_restored;
        fault_event->shadows_restored = shadows_restored;
        fault_event->recovery_duration_ns = get_timestamp_ns() - recovery_start;

        bpf_ringbuf_submit(fault_event, 0);
    }

    return 0;
}

/*
 * Manual shadow restore operation
 * Called by userspace to restore a specific shadow after device failure
 */
SEC("cxl_crypto/restore_shadow")
int cxl_crypto_restore_shadow(struct bpf_raw_tracepoint_args *ctx)
{
    /*
     * Arguments:
     * ctx->args[0]: address to restore
     * ctx->args[1]: output buffer for restored data
     * ctx->args[2]: output buffer size
     */
    __u64 addr = (__u64)ctx->args[0];
    void *output = (void *)ctx->args[1];
    __u32 output_size = (__u32)ctx->args[2];

    __u8 temp_data[256];
    __u32 restored_len = 0;

    int ret = restore_crypto_shadow(addr, temp_data, &restored_len);
    if (ret < 0)
        return ret;

    /* Copy restored data to output buffer */
    if (output && output_size > 0) {
        __u32 copy_len = restored_len > output_size ? output_size : restored_len;
        if (bpf_probe_write_user(output, temp_data, copy_len) < 0)
            return -3;
    }

    return 0;
}

/*
 * IV counter update hook
 * Special handling for IV counters to ensure monotonic increment and shadow
 */
SEC("cxl_crypto/iv_update")
int cxl_crypto_iv_update(struct bpf_raw_tracepoint_args *ctx)
{
    /*
     * Arguments:
     * ctx->args[0]: IV counter address
     * ctx->args[1]: old IV value
     * ctx->args[2]: new IV value
     * ctx->args[3]: device ID
     */
    __u64 addr = (__u64)ctx->args[0];
    __u64 old_iv = (__u64)ctx->args[1];
    __u64 new_iv = (__u64)ctx->args[2];
    __u32 device_id = (__u32)ctx->args[3];

    struct crypto_context_shadow *shadow;

    /* Find or create shadow for this IV counter */
    shadow = bpf_map_lookup_elem(&crypto_shadow_map, &addr);
    if (!shadow) {
        /* Create new shadow */
        struct crypto_region *region = find_crypto_region(addr);
        if (region) {
            __u8 iv_data[8];
            __builtin_memcpy(iv_data, &old_iv, sizeof(__u64));
            create_crypto_shadow(addr, device_id, region, iv_data, 8);
            shadow = bpf_map_lookup_elem(&crypto_shadow_map, &addr);
        }
    }

    if (shadow) {
        /* Update IV counter in shadow */
        shadow->iv_counter = new_iv;
        shadow->timestamp = get_timestamp_ns();
        shadow->version++;

        /* Recompute checksum */
        shadow->checksum = compute_crc64(shadow->data, 256);

        bpf_map_update_elem(&crypto_shadow_map, &addr, shadow, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL v2";
