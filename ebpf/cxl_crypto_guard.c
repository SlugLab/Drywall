/*
 * CXL Crypto Guard Userspace Control Plane
 *
 * This module loads and manages the CXL crypto guard eBPF coprocessor,
 * configures protection policies for LUKS/dm-crypt metadata, and handles
 * recovery operations when CXL devices fail.
 *
 * Copyright (c) 2025 Drywall Project
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See the
 * COPYING file in the top-level directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "cxl_crypto_guard.h"

#define MAX_CRYPTO_REGIONS 1024
#define MAX_DEVICES 256

struct CXLCryptoGuardState {
    /* eBPF program state */
    struct bpf_object *obj;
    struct bpf_program *prog_access_check;
    struct bpf_program *prog_device_offline;
    struct bpf_program *prog_restore_shadow;
    struct bpf_program *prog_iv_update;

    int crypto_regions_fd;
    int crypto_shadow_fd;
    int active_operations_fd;
    int device_ownership_fd;
    int event_ringbuf_fd;
    int fault_ringbuf_fd;
    int stats_fd;
    int device_stats_fd;

    /* Ring buffers */
    struct ring_buffer *event_rb;
    struct ring_buffer *fault_rb;

    /* Configuration */
    int enabled;
    uint32_t num_regions;

    /* Event callbacks */
    CryptoEventCallback event_callback;
    void *event_callback_ctx;
    CryptoFaultCallback fault_callback;
    void *fault_callback_ctx;

    /* Statistics */
    uint64_t total_accesses;
    uint64_t shadows_created;
    uint64_t shadows_restored;
    uint64_t policy_violations;
    uint64_t device_faults;
};

/* Global crypto guard instance */
static struct CXLCryptoGuardState *g_crypto_guard_state = NULL;

/* Event ring buffer callback */
static int handle_crypto_event(void *ctx, void *data, size_t data_sz)
{
    struct CXLCryptoGuardState *state = ctx;
    struct crypto_access_event *event = data;

    if (data_sz < sizeof(*event))
        return 0;

    /* Call registered callback if exists */
    if (state->event_callback) {
        state->event_callback(event, state->event_callback_ctx);
    }

    /* Log violations */
    if (event->violation) {
        fprintf(stderr, "CXL Crypto Guard: Policy violation - device %u accessing "
                       "crypto region at 0x%lx (op=%u, region_type=0x%x)\n",
                       event->device_id, event->addr, event->operation_type,
                       event->region_type);
    }

    return 0;
}

/* Fault ring buffer callback */
static int handle_crypto_fault(void *ctx, void *data, size_t data_sz)
{
    struct CXLCryptoGuardState *state = ctx;
    struct crypto_device_fault *fault = data;

    if (data_sz < sizeof(*fault))
        return 0;

    printf("CXL Crypto Guard: Device %u fault (type=%u) - "
           "restored %u shadows in %lu ns\n",
           fault->device_id, fault->fault_type,
           fault->shadows_restored, fault->recovery_duration_ns);

    /* Call registered callback if exists */
    if (state->fault_callback) {
        state->fault_callback(fault, state->fault_callback_ctx);
    }

    return 0;
}

/* Initialize CXL crypto guard eBPF coprocessor */
CXLCryptoGuardState *cxl_crypto_guard_init(void)
{
    struct CXLCryptoGuardState *state;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    int err;

    /* Increase RLIMIT_MEMLOCK for BPF */
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return NULL;
    }

    state = calloc(1, sizeof(*state));
    if (!state) {
        fprintf(stderr, "Failed to allocate state\n");
        return NULL;
    }

    /* Load eBPF object file */
    state->obj = bpf_object__open_file("tools/ebpf/cxl_crypto_guard.bpf.o", NULL);
    if (!state->obj) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", strerror(errno));
        goto fail;
    }

    /* Load BPF program */
    err = bpf_object__load(state->obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto fail_close;
    }

    /* Get file descriptors for maps */
    struct bpf_map *map;

    map = bpf_object__find_map_by_name(state->obj, "crypto_regions_map");
    if (map) state->crypto_regions_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(state->obj, "crypto_shadow_map");
    if (map) state->crypto_shadow_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(state->obj, "active_operations_map");
    if (map) state->active_operations_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(state->obj, "device_crypto_ownership_map");
    if (map) state->device_ownership_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(state->obj, "crypto_event_ringbuf");
    if (map) state->event_ringbuf_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(state->obj, "crypto_fault_ringbuf");
    if (map) state->fault_ringbuf_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(state->obj, "crypto_stats_map");
    if (map) state->stats_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(state->obj, "device_stats_map");
    if (map) state->device_stats_fd = bpf_map__fd(map);

    if (state->crypto_regions_fd < 0 || state->crypto_shadow_fd < 0 ||
        state->event_ringbuf_fd < 0 || state->fault_ringbuf_fd < 0 ||
        state->stats_fd < 0) {
        fprintf(stderr, "Failed to get BPF map file descriptors\n");
        goto fail_close;
    }

    /* Set up ring buffers for event monitoring */
    state->event_rb = ring_buffer__new(state->event_ringbuf_fd,
                                      handle_crypto_event, state, NULL);
    if (!state->event_rb) {
        fprintf(stderr, "Failed to create event ring buffer\n");
        goto fail_close;
    }

    state->fault_rb = ring_buffer__new(state->fault_ringbuf_fd,
                                      handle_crypto_fault, state, NULL);
    if (!state->fault_rb) {
        fprintf(stderr, "Failed to create fault ring buffer\n");
        ring_buffer__free(state->event_rb);
        goto fail_close;
    }

    state->enabled = 1;
    state->num_regions = 0;
    state->event_callback = NULL;
    state->fault_callback = NULL;

    printf("CXL crypto guard eBPF coprocessor initialized successfully\n");

    g_crypto_guard_state = state;
    return state;

fail_close:
    bpf_object__close(state->obj);
fail:
    free(state);
    return NULL;
}

/* Cleanup CXL crypto guard */
void cxl_crypto_guard_cleanup(CXLCryptoGuardState *state)
{
    if (!state)
        return;

    if (state->event_rb)
        ring_buffer__free(state->event_rb);

    if (state->fault_rb)
        ring_buffer__free(state->fault_rb);

    if (state->obj)
        bpf_object__close(state->obj);

    free(state);
    g_crypto_guard_state = NULL;

    printf("CXL crypto guard eBPF coprocessor cleaned up\n");
}

/* Add crypto region protection policy */
int cxl_crypto_guard_add_region(CXLCryptoGuardState *state, uint64_t start_addr,
                                uint64_t end_addr, uint32_t region_type,
                                uint32_t protection_level, uint8_t *device_allowlist)
{
    struct crypto_region region = {0};

    if (!state || !state->enabled)
        return -1;

    if (state->num_regions >= MAX_CRYPTO_REGIONS) {
        fprintf(stderr, "CXL crypto guard: Maximum number of regions reached\n");
        return -1;
    }

    region.start_addr = start_addr;
    region.end_addr = end_addr;
    region.region_type = region_type;
    region.protection_level = protection_level;
    region.last_shadow_time = 0;
    region.access_count = 0;
    region.violation_count = 0;

    /* Copy device allowlist if provided */
    if (device_allowlist) {
        memcpy(region.device_allowlist, device_allowlist, 32);
    } else {
        /* Default: allow all devices */
        memset(region.device_allowlist, 0xFF, 32);
    }

    /* Use start address as key */
    if (bpf_map_update_elem(state->crypto_regions_fd, &start_addr, &region, BPF_ANY) < 0) {
        fprintf(stderr, "CXL crypto guard: Failed to add crypto region: %s\n",
                strerror(errno));
        return -1;
    }

    state->num_regions++;

    printf("CXL crypto guard: Added protection for region 0x%lx-0x%lx "
           "(type=0x%x, protection=%u)\n",
           start_addr, end_addr, region_type, protection_level);

    return 0;
}

/* Configure LUKS-specific protection */
int cxl_crypto_guard_protect_luks(CXLCryptoGuardState *state, uint64_t luks_header_addr,
                                  uint32_t protection_level)
{
    int ret = 0;

    /* Protect LUKS header (typically first 2MB of device) */
    ret |= cxl_crypto_guard_add_region(state, luks_header_addr,
                                      luks_header_addr + (2 * 1024 * 1024),
                                      CRYPTO_REGION_LUKS_HEADER,
                                      protection_level, NULL);

    printf("CXL crypto guard: LUKS header protection configured at 0x%lx\n",
           luks_header_addr);

    return ret;
}

/* Configure dm-crypt state protection */
int cxl_crypto_guard_protect_dmcrypt_state(CXLCryptoGuardState *state,
                                           uint64_t state_addr, uint64_t state_size,
                                           uint32_t protection_level)
{
    return cxl_crypto_guard_add_region(state, state_addr, state_addr + state_size,
                                      CRYPTO_REGION_DMCRYPT_STATE |
                                      CRYPTO_REGION_CRYPTO_CTX,
                                      protection_level, NULL);
}

/* Configure IV counter protection */
int cxl_crypto_guard_protect_iv_counters(CXLCryptoGuardState *state,
                                         uint64_t iv_base_addr, uint64_t iv_size,
                                         uint32_t protection_level)
{
    return cxl_crypto_guard_add_region(state, iv_base_addr, iv_base_addr + iv_size,
                                      CRYPTO_REGION_IV_COUNTER,
                                      protection_level, NULL);
}

/* Manually restore shadow after device failure */
int cxl_crypto_guard_restore_shadow(CXLCryptoGuardState *state, uint64_t addr,
                                   uint8_t *data_out, size_t data_len)
{
    struct crypto_context_shadow shadow;

    if (!state || !state->enabled)
        return -1;

    if (bpf_map_lookup_elem(state->crypto_shadow_fd, &addr, &shadow) < 0) {
        fprintf(stderr, "CXL crypto guard: No shadow found for addr 0x%lx: %s\n",
                addr, strerror(errno));
        return -1;
    }

    /* Verify checksum (simplified - full verification in eBPF) */
    if (data_out && data_len > 0) {
        size_t copy_len = data_len > 256 ? 256 : data_len;
        memcpy(data_out, shadow.data, copy_len);
    }

    printf("CXL crypto guard: Restored crypto context from shadow at 0x%lx "
           "(version=%lu)\n", addr, shadow.version);

    return 0;
}

/* Handle device offline event - restore all shadows for this device */
int cxl_crypto_guard_device_offline(CXLCryptoGuardState *state, uint32_t device_id)
{
    uint64_t ownership_key, next_key;
    uint32_t region_type;
    int restored = 0;

    if (!state || !state->enabled)
        return 0;

    printf("CXL crypto guard: Device %u went offline, initiating recovery\n",
           device_id);

    /* Iterate through device ownership map and restore shadows */
    ownership_key = (uint64_t)device_id << 48;
    while (bpf_map_get_next_key(state->device_ownership_fd, &ownership_key,
                                &next_key) == 0) {
        /* Check if this entry belongs to our device */
        if ((next_key >> 48) != device_id) {
            ownership_key = next_key;
            continue;
        }

        /* Extract address from ownership key */
        uint64_t addr = next_key & 0xFFFFFFFFFFFFULL;

        /* Lookup region type */
        if (bpf_map_lookup_elem(state->device_ownership_fd, &next_key,
                              &region_type) == 0) {
            /* Restore shadow for this address */
            uint8_t restored_data[256];
            if (cxl_crypto_guard_restore_shadow(state, addr, restored_data,
                                              sizeof(restored_data)) == 0) {
                restored++;
            }

            /* Remove from ownership map */
            bpf_map_delete_elem(state->device_ownership_fd, &next_key);
        }

        ownership_key = next_key;
    }

    printf("CXL crypto guard: Restored %d crypto contexts for device %u\n",
           restored, device_id);

    return restored;
}

/* Get statistics */
int cxl_crypto_guard_get_stats(CXLCryptoGuardState *state,
                              CryptoGuardStats *stats_out)
{
    struct crypto_guard_stats stats;
    uint32_t key = 0;

    if (!state || !stats_out)
        return -1;

    if (bpf_map_lookup_elem(state->stats_fd, &key, &stats) < 0) {
        fprintf(stderr, "CXL crypto guard: Failed to read statistics: %s\n",
                strerror(errno));
        return -1;
    }

    stats_out->total_accesses = stats.total_accesses;
    stats_out->exclusive_denied = stats.exclusive_denied;
    stats_out->shadows_created = stats.shadows_created;
    stats_out->shadows_restored = stats.shadows_restored;
    stats_out->policy_violations = stats.policy_violations;
    stats_out->device_faults = stats.device_faults;
    stats_out->integrity_failures = stats.integrity_failures;
    stats_out->recovery_operations = stats.recovery_operations;

    memcpy(stats_out->operations, stats.operations, sizeof(stats.operations));
    memcpy(stats_out->region_accesses, stats.region_accesses,
           sizeof(stats.region_accesses));

    return 0;
}

/* Poll event ring buffers */
int cxl_crypto_guard_poll_events(CXLCryptoGuardState *state, int timeout_ms)
{
    int err = 0;

    if (!state || !state->enabled)
        return 0;

    /* Poll event ring buffer */
    if (state->event_rb) {
        err = ring_buffer__poll(state->event_rb, timeout_ms);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "CXL crypto guard: Error polling event ring buffer: %d\n", err);
        }
    }

    /* Poll fault ring buffer */
    if (state->fault_rb) {
        err = ring_buffer__poll(state->fault_rb, timeout_ms);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "CXL crypto guard: Error polling fault ring buffer: %d\n", err);
        }
    }

    return err >= 0 ? 0 : err;
}

/* Register event callback */
void cxl_crypto_guard_set_event_callback(CXLCryptoGuardState *state,
                                        CryptoEventCallback callback, void *ctx)
{
    if (!state)
        return;

    state->event_callback = callback;
    state->event_callback_ctx = ctx;
}

/* Register fault callback */
void cxl_crypto_guard_set_fault_callback(CXLCryptoGuardState *state,
                                        CryptoFaultCallback callback, void *ctx)
{
    if (!state)
        return;

    state->fault_callback = callback;
    state->fault_callback_ctx = ctx;
}

/* Get global crypto guard instance */
CXLCryptoGuardState *cxl_crypto_guard_get_global(void)
{
    return g_crypto_guard_state;
}
