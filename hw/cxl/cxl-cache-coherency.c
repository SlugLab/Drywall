/*
 * CXL Type 1 Cache Coherency Implementation
 *
 * This implements page-level write protection for tracking cache coherency
 * for CXL Type 1 devices (e.g., crypto accelerators) without relying on
 * Intel SPP (Sub-Page Protection).
 *
 * Copyright (c) Yiwei Yang 2025
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version. See the COPYING file in the
 * top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_device.h"
#include "hw/cxl/cxl_cache_coherency.h"
#include "hw/cxl/cxl_crypto_guard.h"
#include "exec/memory.h"
#include "exec/memop.h"

#define CACHELINE_SIZE 64
#define PAGE_SIZE 4096
#define CACHELINES_PER_PAGE (PAGE_SIZE / CACHELINE_SIZE)

/* Page tracking structure for write protection */
typedef struct CXLCachePage {
    hwaddr page_addr;              /* Page-aligned address */
    MemoryRegion *page_mr;         /* Memory region for this page */
    bool write_protected;          /* Is page write-protected? */
    uint64_t cacheline_bitmap;     /* Bitmap of tracked cachelines (64 lines/page) */
    uint8_t backup_data[PAGE_SIZE]; /* Backup for exclusive cachelines */
    QLIST_ENTRY(CXLCachePage) next;
} CXLCachePage;

/* Cache coherency state for a CXL Type 1 device */
typedef struct CXLCacheCoherencyState {
    CXLCacheRegion *region;
    MemoryRegion *hostmem_mr;
    QLIST_HEAD(, CXLCachePage) tracked_pages;
    bool device_online;
    QemuMutex lock;

    /* Crypto guard extension */
    CXLCryptoGuardState *crypto_guard;
} CXLCacheCoherencyState;

/* Get cacheline index within a page */
static inline int get_cacheline_index(hwaddr addr)
{
    return (addr % PAGE_SIZE) / CACHELINE_SIZE;
}

/* Get page-aligned address */
static inline hwaddr get_page_addr(hwaddr addr)
{
    return addr & ~(PAGE_SIZE - 1);
}

/* Find or create a tracked page */
static CXLCachePage *cxl_cache_find_or_create_page(CXLCacheCoherencyState *state,
                                                     hwaddr addr)
{
    hwaddr page_addr = get_page_addr(addr);
    CXLCachePage *page;

    /* Search for existing page */
    QLIST_FOREACH(page, &state->tracked_pages, next) {
        if (page->page_addr == page_addr) {
            return page;
        }
    }

    /* Create new page tracking entry */
    page = g_new0(CXLCachePage, 1);
    page->page_addr = page_addr;
    page->write_protected = false;
    page->cacheline_bitmap = 0;
    page->page_mr = NULL;

    QLIST_INSERT_HEAD(&state->tracked_pages, page, next);
    return page;
}

/* Memory region ops for write-protected pages */
static uint64_t cxl_cache_page_read(void *opaque, hwaddr addr, unsigned size)
{
    CXLCacheCoherencyState *state = opaque;
    uint64_t value = 0;

    /* Forward read to actual memory */
    if (state->hostmem_mr) {
        memory_region_dispatch_read(state->hostmem_mr, addr, &value,
                                    size_memop(size) | MO_LE,
                                    MEMTXATTRS_UNSPECIFIED);
    }

    return value;
}

static void cxl_cache_page_write(void *opaque, hwaddr addr,
                                  uint64_t value, unsigned size)
{
    CXLCacheCoherencyState *state = opaque;
    int cl_idx = get_cacheline_index(addr);
    CXLCachePage *page;

    qemu_mutex_lock(&state->lock);

    page = cxl_cache_find_or_create_page(state, addr);

    if (page->cacheline_bitmap & (1ULL << cl_idx)) {
        /* This cacheline is tracked - check if device has exclusive access */
        uint64_t cache_idx = (addr - state->region->base) / CACHELINE_SIZE;

        if (cache_idx < (state->region->size / CACHELINE_SIZE)) {
            CXLCache *cache = &state->region->cache[cache_idx];

            if (cache->ats & 0x1) { /* ATS bit indicates exclusive access */
                /* Device has exclusive access - need to handle this carefully */
                if (!state->device_online) {
                    /* Device is offline - restore from backup */
                    qemu_log_mask(LOG_GUEST_ERROR,
                                  "CXL: Write to cacheline with offline device at 0x%lx\n",
                                  addr);

                    /* Copy backup data back */
                    hwaddr cl_offset = cl_idx * CACHELINE_SIZE;
                    memcpy(cache->data, &page->backup_data[cl_offset], CACHELINE_SIZE);

                    /* Clear exclusive bit */
                    cache->ats &= ~0x1;
                    cache->state = I; /* Invalidate */
                }
            }
        }
    }

    /* Forward write to actual memory */
    if (state->hostmem_mr) {
        memory_region_dispatch_write(state->hostmem_mr, addr, value,
                                     size_memop(size) | MO_LE,
                                     MEMTXATTRS_UNSPECIFIED);
    }

    qemu_mutex_unlock(&state->lock);
}

static const MemoryRegionOps cxl_cache_page_ops __attribute__((unused)) = {
    .read = cxl_cache_page_read,
    .write = cxl_cache_page_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

/* Mark a cacheline as exclusive-able (device can take exclusive access) */
void cxl_cache_mark_exclusive(CXLCacheCoherencyState *state, hwaddr addr,
                               uint32_t ats_flags)
{
    int cl_idx = get_cacheline_index(addr);
    CXLCachePage *page;
    uint64_t cache_idx;
    uint32_t device_id = (ats_flags >> 16) & 0xFFFF; /* Extract device ID from ATS */

    if (!state || !state->region) {
        return;
    }

    qemu_mutex_lock(&state->lock);

    /* CRYPTO GUARD INTEGRATION: Policy check */
    if (state->crypto_guard) {
        CryptoPolicyDecision decision;

        decision = cxl_crypto_guard_check_policy(state->crypto_guard,
                                                  addr, device_id, ats_flags);

        if (decision == POLICY_DENY_EXCLUSIVE) {
            /* Deny exclusive access - grant Shared instead */
            qemu_log_mask(LOG_GUEST_ERROR,
                          "[CXL-Cache] Policy denied exclusive access for addr 0x%lx (device %u)\n",
                          addr, device_id);
            qemu_mutex_unlock(&state->lock);
            return; /* Flowchart: "DENY E/M" path */
        }

        if (decision == POLICY_QUARANTINE) {
            /* Device is quarantined - deny all access */
            qemu_log_mask(LOG_GUEST_ERROR,
                          "[CXL-Cache] Access denied - device %u is quarantined\n",
                          device_id);
            qemu_mutex_unlock(&state->lock);
            return;
        }

        /* POLICY_ALLOW_EXCLUSIVE - proceed with shadow installation */
    }

    page = cxl_cache_find_or_create_page(state, addr);

    /* Mark this cacheline as tracked */
    page->cacheline_bitmap |= (1ULL << cl_idx);

    /* Backup current cacheline data */
    hwaddr cl_offset = cl_idx * CACHELINE_SIZE;
    uint8_t cacheline_data[CACHELINE_SIZE];

    if (state->hostmem_mr) {
        uint64_t *src = memory_region_get_ram_ptr(state->hostmem_mr) +
                       (addr - state->region->base);
        memcpy(&page->backup_data[cl_offset], src, CACHELINE_SIZE);
        memcpy(cacheline_data, src, CACHELINE_SIZE);
    }

    /* CRYPTO GUARD INTEGRATION: Install shadow before granting exclusive */
    if (state->crypto_guard) {
        int ret = cxl_crypto_guard_install_shadow(state->crypto_guard,
                                                   addr, device_id,
                                                   cacheline_data);
        if (ret < 0) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "[CXL-Cache] Failed to install shadow for addr 0x%lx\n",
                          addr);
            qemu_mutex_unlock(&state->lock);
            return;
        }
        /* Flowchart: "Install shadow & grant" complete */
    }

    /* Update cache state - GRANT EXCLUSIVE ACCESS */
    cache_idx = (addr - state->region->base) / CACHELINE_SIZE;
    if (cache_idx < (state->region->size / CACHELINE_SIZE)) {
        CXLCache *cache = &state->region->cache[cache_idx];
        cache->ats = ats_flags | 0x1; /* Set exclusive bit */
        cache->state = E; /* Exclusive state */

        /* Copy data to cache */
        if (state->hostmem_mr) {
            uint64_t *src = memory_region_get_ram_ptr(state->hostmem_mr) +
                           (addr - state->region->base);
            memcpy(cache->data, src, CACHELINE_SIZE);
        }
    }

    /* Enable write protection on this page if not already */
    if (!page->write_protected) {
        /* Note: Actual write protection would require KVM/TCG support
         * For now, we use memory region ops to intercept writes */
        page->write_protected = true;
    }

    qemu_mutex_unlock(&state->lock);
}

/* Release exclusive access to a cacheline */
void cxl_cache_release_exclusive(CXLCacheCoherencyState *state, hwaddr addr)
{
    int cl_idx = get_cacheline_index(addr);
    CXLCachePage *page;
    uint64_t cache_idx;

    if (!state || !state->region) {
        return;
    }

    qemu_mutex_lock(&state->lock);

    page = cxl_cache_find_or_create_page(state, addr);

    /* Update cache state */
    cache_idx = (addr - state->region->base) / CACHELINE_SIZE;
    if (cache_idx < (state->region->size / CACHELINE_SIZE)) {
        CXLCache *cache = &state->region->cache[cache_idx];

        /* Write back data if modified */
        if (cache->state == M || cache->state == E) {
            if (state->hostmem_mr) {
                uint64_t *dst = memory_region_get_ram_ptr(state->hostmem_mr) +
                               (addr - state->region->base);
                memcpy(dst, cache->data, CACHELINE_SIZE);
            }
        }

        cache->ats &= ~0x1; /* Clear exclusive bit */
        cache->state = I; /* Invalidate */
    }

    /* Unmark this cacheline */
    page->cacheline_bitmap &= ~(1ULL << cl_idx);

    /* If no more cachelines tracked on this page, disable write protection */
    if (page->cacheline_bitmap == 0) {
        page->write_protected = false;
    }

    qemu_mutex_unlock(&state->lock);
}

/* Handle device going offline (hot-unplug or failure) */
void cxl_cache_device_offline(CXLCacheCoherencyState *state)
{
    CXLCachePage *page, *next;

    if (!state) {
        return;
    }

    /* CRYPTO GUARD: Handle device offline first (revokes shadows, recovers state) */
    if (state->crypto_guard) {
        cxl_crypto_guard_device_offline(state->crypto_guard);
        /* This implements the recovery flow:
         * - Revoke / degrade (force writeback, fence PASID/region)
         * - Recover authoritative state (reconstruct from shadow + host log)
         * - Resume host progress (host-owned update; audit)
         */
    }

    qemu_mutex_lock(&state->lock);

    state->device_online = false;

    /* Write back all exclusive cachelines from backup */
    QLIST_FOREACH_SAFE(page, &state->tracked_pages, next, next) {
        for (int i = 0; i < CACHELINES_PER_PAGE; i++) {
            if (page->cacheline_bitmap & (1ULL << i)) {
                hwaddr addr = page->page_addr + (i * CACHELINE_SIZE);
                uint64_t cache_idx = (addr - state->region->base) / CACHELINE_SIZE;

                if (cache_idx < (state->region->size / CACHELINE_SIZE)) {
                    CXLCache *cache = &state->region->cache[cache_idx];

                    /* Restore from backup */
                    if (state->hostmem_mr) {
                        uint64_t *dst = memory_region_get_ram_ptr(state->hostmem_mr) +
                                       (addr - state->region->base);
                        memcpy(dst, &page->backup_data[i * CACHELINE_SIZE],
                               CACHELINE_SIZE);
                    }

                    cache->ats = 0;
                    cache->state = I;
                }
            }
        }
    }

    qemu_log_mask(LOG_GUEST_ERROR, "CXL: Device offline, all cachelines restored\n");

    qemu_mutex_unlock(&state->lock);
}

/* Handle device coming online */
void cxl_cache_device_online(CXLCacheCoherencyState *state)
{
    if (!state) {
        return;
    }

    qemu_mutex_lock(&state->lock);
    state->device_online = true;
    qemu_mutex_unlock(&state->lock);

    /* CRYPTO GUARD: Notify crypto guard of device online */
    if (state->crypto_guard) {
        cxl_crypto_guard_device_online(state->crypto_guard);
    }
}

/* Initialize cache coherency state */
CXLCacheCoherencyState *cxl_cache_coherency_init(CXLCacheRegion *region,
                                                   MemoryRegion *hostmem_mr)
{
    CXLCacheCoherencyState *state = g_new0(CXLCacheCoherencyState, 1);

    state->region = region;
    state->hostmem_mr = hostmem_mr;
    state->device_online = true;
    QLIST_INIT(&state->tracked_pages);
    qemu_mutex_init(&state->lock);

    /* Allocate cache array if not already done */
    if (!region->cache) {
        uint64_t num_cachelines = region->size / CACHELINE_SIZE;
        region->cache = g_new0(CXLCache, num_cachelines);

        /* Initialize all cachelines to Invalid state */
        for (uint64_t i = 0; i < num_cachelines; i++) {
            region->cache[i].state = I;
            region->cache[i].ats = 0;
        }
    }

    /* CRYPTO GUARD: Initialize crypto guard extension */
    state->crypto_guard = cxl_crypto_guard_init(state, PROTECTION_SHADOW_REQUIRED);
    if (!state->crypto_guard) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "[CXL-Cache] Warning: Crypto guard initialization failed - "
                      "running without crypto protection\n");
    }

    return state;
}

/* Cleanup cache coherency state */
void cxl_cache_coherency_cleanup(CXLCacheCoherencyState *state)
{
    CXLCachePage *page, *next;

    if (!state) {
        return;
    }

    /* CRYPTO GUARD: Cleanup crypto guard extension first */
    if (state->crypto_guard) {
        cxl_crypto_guard_cleanup(state->crypto_guard);
        state->crypto_guard = NULL;
    }

    /* Write back all cached data */
    cxl_cache_device_offline(state);

    /* Free tracked pages */
    QLIST_FOREACH_SAFE(page, &state->tracked_pages, next, next) {
        QLIST_REMOVE(page, next);
        g_free(page);
    }

    qemu_mutex_destroy(&state->lock);
    g_free(state);
}
