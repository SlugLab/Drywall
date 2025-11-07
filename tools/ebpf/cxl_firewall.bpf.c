/*
 * CXL Firewall eBPF Coprocessor
 *
 * This eBPF program monitors CXL cache coherency operations, enforces
 * ATS-tagged exclusivity policies, tracks shadow cache state, and logs
 * coherence protocol violations for fault injection testing.
 *
 * Copyright (c) 2025 Drywall Project
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See the
 * COPYING file in the top-level directory.
 *
 * Build:
 * make -f Makefile.ebpf.cxl clean all
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>

/* Cacheline size for CXL */
#define CACHELINE_SIZE 64
#define MAX_CACHELINES 65536  /* Track up to 4MB worth of cachelines */
#define PAGE_SIZE 4096
#define CACHELINES_PER_PAGE (PAGE_SIZE / CACHELINE_SIZE)

/* MESI coherence states */
enum cxl_coherence_state {
    CXL_STATE_INVALID = 0,
    CXL_STATE_SHARED = 1,
    CXL_STATE_EXCLUSIVE = 2,
    CXL_STATE_MODIFIED = 3,
};

/* ATS (Address Translation Service) policy flags */
#define ATS_FLAG_READ           (1 << 0)
#define ATS_FLAG_WRITE          (1 << 1)
#define ATS_FLAG_EXCLUSIVE      (1 << 2)
#define ATS_FLAG_PROTECTED      (1 << 3)  /* Critical kernel region */
#define ATS_FLAG_SHADOWED       (1 << 4)  /* Has shadow backup */
#define ATS_FLAG_DEVICE_OWNED   (1 << 5)  /* Device has exclusive ownership */

/* CXL cache transaction types */
enum cxl_transaction_type {
    CXL_TXN_READ_SHARED = 0,     /* ReadCurr - request shared access */
    CXL_TXN_READ_EXCLUSIVE = 1,  /* DirtyRead - request exclusive access */
    CXL_TXN_WRITEBACK = 2,       /* WriteBack - return modified data */
    CXL_TXN_EVICT = 3,           /* SnpInv - evict from cache */
    CXL_TXN_INVALIDATE = 4,      /* Host requests invalidation */
    CXL_TXN_REVOKE = 5,          /* Host revokes exclusive access */
};

/* Shadow cacheline metadata */
struct shadow_cacheline {
    __u64 addr;                  /* Physical address */
    __u64 timestamp;             /* Last access time (ns) */
    __u64 version;               /* Monotonic version counter */
    __u32 device_id;             /* Owning device identifier */
    __u32 ats_flags;             /* ATS policy flags */
    __u8 state;                  /* MESI state */
    __u8 data[CACHELINE_SIZE];   /* Shadow data backup */
    __u8 checksum[8];            /* Quick integrity check (CRC64) */
} __attribute__((packed));

/* ATS policy entry */
struct ats_policy {
    __u64 start_addr;            /* Start of protected region */
    __u64 end_addr;              /* End of protected region */
    __u32 policy_flags;          /* Allowed ATS operations */
    __u32 device_mask;           /* Bitmask of allowed devices */
    __u8 allow_exclusive;        /* Can devices get exclusive access? */
    __u8 require_shadow;         /* Must create shadow before exclusive */
    __u8 priority;               /* Policy priority (higher = more restrictive) */
} __attribute__((packed));

/* Transaction event for logging and introspection */
struct cxl_transaction_event {
    __u64 timestamp;             /* Event timestamp (ns) */
    __u64 addr;                  /* Cacheline address */
    __u32 device_id;             /* Device performing transaction */
    __u32 transaction_type;      /* Type of transaction */
    __u32 ats_flags;             /* Requested ATS flags */
    __u32 policy_flags;          /* Matched policy flags */
    __u8 old_state;              /* Previous MESI state */
    __u8 new_state;              /* New MESI state */
    __u8 allowed;                /* Was transaction allowed? */
    __u8 fault_injected;         /* Was a fault injected? */
} __attribute__((packed));

/* Fault injection configuration */
struct fault_injection_config {
    __u32 enabled;               /* Is fault injection enabled? */
    __u32 inject_rate;           /* Rate: 1 in N transactions */
    __u32 fault_type;            /* Type of fault to inject */
    __u32 target_device;         /* Target device (0 = all) */
    __u64 target_addr_start;     /* Target address range start */
    __u64 target_addr_end;       /* Target address range end */
} __attribute__((packed));

/* Fault types for injection */
enum fault_type {
    FAULT_NONE = 0,
    FAULT_DELAYED_REVOKE = 1,    /* Delay response to revoke request */
    FAULT_SILENT_DROP = 2,        /* Drop transaction silently */
    FAULT_CORRUPT_DATA = 3,       /* Corrupt cacheline data */
    FAULT_STATE_VIOLATION = 4,    /* Invalid state transition */
    FAULT_HOT_UNPLUG = 5,        /* Simulate device removal */
};

/* Statistics counters */
struct cxl_statistics {
    __u64 total_transactions;
    __u64 exclusive_grants;
    __u64 exclusive_revokes;
    __u64 policy_violations;
    __u64 shadow_creates;
    __u64 shadow_restores;
    __u64 faults_injected;
    __u64 state_transitions[4][4]; /* [old_state][new_state] */
};

/* ========== BPF Maps ========== */

/* Map: Shadow cacheline store (device-private DRAM simulation) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CACHELINES);
    __type(key, __u64);   /* Cacheline address */
    __type(value, struct shadow_cacheline);
} shadow_cache_map SEC(".maps");

/* Map: ATS exclusivity policies */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);  /* Support up to 256 policy regions */
    __type(key, __u32);
    __type(value, struct ats_policy);
} ats_policy_map SEC(".maps");

/* Map: Transaction event ring buffer for logging */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256KB ring buffer */
} event_ringbuf SEC(".maps");

/* Map: Fault injection configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fault_injection_config);
} fault_config_map SEC(".maps");

/* Map: Statistics counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cxl_statistics);
} stats_map SEC(".maps");

/* Map: Current device ownership tracking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CACHELINES);
    __type(key, __u64);   /* Cacheline address */
    __type(value, __u32); /* Device ID */
} ownership_map SEC(".maps");

/* ========== Helper Functions ========== */

static __always_inline __u64 get_cacheline_addr(__u64 addr)
{
    return addr & ~(CACHELINE_SIZE - 1);
}

static __always_inline __u64 get_timestamp_ns(void)
{
    return bpf_ktime_get_ns();
}

/* Simple CRC64 checksum for integrity verification */
static __always_inline __u64 compute_checksum(__u8 *data, __u32 len)
{
    __u64 crc = 0xFFFFFFFFFFFFFFFFULL;
    const __u64 poly = 0x42F0E1EBA9EA3693ULL;

    #pragma unroll
    for (__u32 i = 0; i < CACHELINE_SIZE && i < len; i++) {
        crc ^= (__u64)data[i];
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ poly;
            else
                crc = crc >> 1;
        }
    }

    return ~crc;
}

/* Check if address falls within a policy region */
static __always_inline int check_policy(__u64 addr, __u32 device_id,
                                        __u32 requested_flags,
                                        struct ats_policy **matched_policy)
{
    struct ats_policy *policy;

    /* Iterate through policies to find matching region */
    #pragma unroll
    for (__u32 i = 0; i < 256; i++) {
        policy = bpf_map_lookup_elem(&ats_policy_map, &i);
        if (!policy || policy->start_addr == 0)
            continue;

        /* Check if address is in this policy's range */
        if (addr >= policy->start_addr && addr < policy->end_addr) {
            /* Check device is allowed */
            if (policy->device_mask && !(policy->device_mask & (1 << device_id)))
                return 0;  /* Device not allowed */

            /* Check if requested flags are permitted */
            if ((requested_flags & ATS_FLAG_EXCLUSIVE) && !policy->allow_exclusive)
                return 0;  /* Exclusive access denied */

            if (matched_policy)
                *matched_policy = policy;
            return 1;  /* Policy allows access */
        }
    }

    /* No specific policy - default allow for non-protected regions */
    return 1;
}

/* Create shadow backup before granting exclusive access */
static __always_inline int create_shadow(__u64 addr, __u32 device_id,
                                         __u32 ats_flags, __u8 *data)
{
    struct shadow_cacheline shadow = {0};
    __u64 cl_addr = get_cacheline_addr(addr);

    shadow.addr = cl_addr;
    shadow.timestamp = get_timestamp_ns();
    shadow.device_id = device_id;
    shadow.ats_flags = ats_flags | ATS_FLAG_SHADOWED;
    shadow.state = CXL_STATE_EXCLUSIVE;
    shadow.version = 1; /* TODO: increment from previous version */

    /* Copy data to shadow */
    __builtin_memcpy(shadow.data, data, CACHELINE_SIZE);

    /* Compute checksum */
    __u64 checksum = compute_checksum(data, CACHELINE_SIZE);
    __builtin_memcpy(shadow.checksum, &checksum, sizeof(__u64));

    /* Store shadow in map */
    if (bpf_map_update_elem(&shadow_cache_map, &cl_addr, &shadow, BPF_ANY) < 0)
        return -1;

    /* Update statistics */
    __u32 zero = 0;
    struct cxl_statistics *stats = bpf_map_lookup_elem(&stats_map, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->shadow_creates, 1);

    return 0;
}

/* Restore from shadow when device fails or releases exclusive access */
static __always_inline int restore_from_shadow(__u64 addr, __u8 *data_out)
{
    __u64 cl_addr = get_cacheline_addr(addr);
    struct shadow_cacheline *shadow;

    shadow = bpf_map_lookup_elem(&shadow_cache_map, &cl_addr);
    if (!shadow)
        return -1;  /* No shadow exists */

    /* Verify checksum */
    __u64 checksum = compute_checksum(shadow->data, CACHELINE_SIZE);
    __u64 stored_checksum;
    __builtin_memcpy(&stored_checksum, shadow->checksum, sizeof(__u64));

    if (checksum != stored_checksum)
        return -2;  /* Checksum mismatch - shadow corrupted */

    /* Copy shadow data to output */
    if (data_out)
        __builtin_memcpy(data_out, shadow->data, CACHELINE_SIZE);

    /* Update statistics */
    __u32 zero = 0;
    struct cxl_statistics *stats = bpf_map_lookup_elem(&stats_map, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->shadow_restores, 1);

    return 0;
}

/* Check if fault injection should occur */
static __always_inline int should_inject_fault(__u64 addr, __u32 device_id,
                                                __u32 *fault_type_out)
{
    __u32 zero = 0;
    struct fault_injection_config *config;

    config = bpf_map_lookup_elem(&fault_config_map, &zero);
    if (!config || !config->enabled)
        return 0;

    /* Check if this device is targeted */
    if (config->target_device != 0 && config->target_device != device_id)
        return 0;

    /* Check if address is in target range */
    if (config->target_addr_start != 0 || config->target_addr_end != 0) {
        if (addr < config->target_addr_start || addr >= config->target_addr_end)
            return 0;
    }

    /* Probabilistic injection based on rate */
    if (config->inject_rate > 0) {
        __u64 rand = bpf_get_prandom_u32();
        if ((rand % config->inject_rate) != 0)
            return 0;
    }

    if (fault_type_out)
        *fault_type_out = config->fault_type;

    /* Update statistics */
    struct cxl_statistics *stats = bpf_map_lookup_elem(&stats_map, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->faults_injected, 1);

    return 1;
}

/* Log transaction event to ring buffer */
static __always_inline void log_event(__u64 addr, __u32 device_id,
                                      __u32 txn_type, __u32 ats_flags,
                                      __u32 policy_flags, __u8 old_state,
                                      __u8 new_state, __u8 allowed,
                                      __u8 fault_injected)
{
    struct cxl_transaction_event *event;

    event = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*event), 0);
    if (!event)
        return;

    event->timestamp = get_timestamp_ns();
    event->addr = addr;
    event->device_id = device_id;
    event->transaction_type = txn_type;
    event->ats_flags = ats_flags;
    event->policy_flags = policy_flags;
    event->old_state = old_state;
    event->new_state = new_state;
    event->allowed = allowed;
    event->fault_injected = fault_injected;

    bpf_ringbuf_submit(event, 0);
}

/* ========== Main Transaction Processing Functions ========== */

/* Process CXL cache transaction with policy enforcement and fault injection */
SEC("cxl_firewall/process_transaction")
int cxl_process_transaction(struct bpf_raw_tracepoint_args *ctx)
{
    /* Extract arguments from context
     * Typically called from QEMU CXL device with:
     * arg0: transaction type
     * arg1: physical address
     * arg2: device ID
     * arg3: requested ATS flags
     * arg4: pointer to cacheline data
     */
    __u32 txn_type = (__u32)ctx->args[0];
    __u64 addr = (__u64)ctx->args[1];
    __u32 device_id = (__u32)ctx->args[2];
    __u32 ats_flags = (__u32)ctx->args[3];
    void *data_ptr = (void *)ctx->args[4];

    __u64 cl_addr = get_cacheline_addr(addr);
    struct ats_policy *policy = NULL;
    __u8 allowed = 1;
    __u8 fault_injected = 0;
    __u32 fault_type = FAULT_NONE;
    __u8 old_state = CXL_STATE_INVALID;
    __u8 new_state = CXL_STATE_INVALID;

    /* Update transaction counter */
    __u32 zero = 0;
    struct cxl_statistics *stats = bpf_map_lookup_elem(&stats_map, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->total_transactions, 1);

    /* Check for fault injection */
    if (should_inject_fault(cl_addr, device_id, &fault_type)) {
        fault_injected = 1;

        switch (fault_type) {
        case FAULT_DELAYED_REVOKE:
            /* Simulate device not responding to revoke within timeout */
            if (txn_type == CXL_TXN_REVOKE) {
                /* Don't process revoke - force timeout path */
                allowed = 0;
            }
            break;

        case FAULT_SILENT_DROP:
            /* Drop transaction entirely */
            allowed = 0;
            break;

        case FAULT_STATE_VIOLATION:
            /* Force invalid state transition */
            new_state = CXL_STATE_MODIFIED;  /* Will be checked below */
            break;

        default:
            break;
        }
    }

    /* Check policy if transaction is requesting exclusive access */
    if (txn_type == CXL_TXN_READ_EXCLUSIVE || (ats_flags & ATS_FLAG_EXCLUSIVE)) {
        if (!check_policy(cl_addr, device_id, ats_flags, &policy)) {
            allowed = 0;
            if (stats)
                __sync_fetch_and_add(&stats->policy_violations, 1);
        }
    }

    /* Process transaction if allowed */
    if (allowed) {
        switch (txn_type) {
        case CXL_TXN_READ_EXCLUSIVE: {
            /* Device requests exclusive access */
            old_state = CXL_STATE_INVALID;  /* Assume transitioning from invalid */
            new_state = CXL_STATE_EXCLUSIVE;

            /* Check if shadowing is required */
            if (policy && policy->require_shadow) {
                /* Create shadow before granting exclusive access */
                __u8 temp_data[CACHELINE_SIZE] = {0};
                if (data_ptr) {
                    bpf_probe_read_kernel(temp_data, CACHELINE_SIZE, data_ptr);
                }

                if (create_shadow(cl_addr, device_id, ats_flags, temp_data) < 0) {
                    allowed = 0;  /* Shadow creation failed */
                    break;
                }
            }

            /* Track ownership */
            bpf_map_update_elem(&ownership_map, &cl_addr, &device_id, BPF_ANY);

            if (stats)
                __sync_fetch_and_add(&stats->exclusive_grants, 1);
            break;
        }

        case CXL_TXN_REVOKE: {
            /* Host revokes exclusive access from device */
            old_state = CXL_STATE_EXCLUSIVE;
            new_state = CXL_STATE_INVALID;

            /* Remove ownership */
            bpf_map_delete_elem(&ownership_map, &cl_addr);

            if (stats)
                __sync_fetch_and_add(&stats->exclusive_revokes, 1);
            break;
        }

        case CXL_TXN_WRITEBACK: {
            /* Device writes back modified data */
            old_state = CXL_STATE_MODIFIED;
            new_state = CXL_STATE_INVALID;

            /* Validate against shadow if exists */
            struct shadow_cacheline *shadow;
            shadow = bpf_map_lookup_elem(&shadow_cache_map, &cl_addr);
            if (shadow) {
                /* Shadow exists - can validate data integrity here */
                /* For now, just delete shadow after writeback */
                bpf_map_delete_elem(&shadow_cache_map, &cl_addr);
            }
            break;
        }

        default:
            break;
        }
    }

    /* Update state transition statistics */
    if (stats && old_state < 4 && new_state < 4) {
        __sync_fetch_and_add(&stats->state_transitions[old_state][new_state], 1);
    }

    /* Log event */
    __u32 policy_flags = policy ? policy->policy_flags : 0;
    log_event(cl_addr, device_id, txn_type, ats_flags, policy_flags,
              old_state, new_state, allowed, fault_injected);

    return allowed ? 0 : -1;
}

/* Handle device offline event (hot-unplug or failure) */
SEC("cxl_firewall/device_offline")
int cxl_device_offline(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 device_id = (__u32)ctx->args[0];

    /* Iterate through ownership map and restore all cachelines owned by this device */
    /* Note: This requires userspace coordination to iterate map entries */

    return 0;
}

char _license[] SEC("license") = "GPL v2";
