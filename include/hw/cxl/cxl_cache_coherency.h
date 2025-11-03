/*
 * CXL Type 1 Cache Coherency Header
 *
 * Copyright (c) Yiwei Yang 2025
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version. See the COPYING file in the
 * top-level directory.
 */

#ifndef CXL_CACHE_COHERENCY_H
#define CXL_CACHE_COHERENCY_H

#include "hw/cxl/cxl.h"
#include "exec/memory.h"

typedef struct CXLCacheCoherencyState CXLCacheCoherencyState;

/**
 * cxl_cache_coherency_init - Initialize cache coherency tracking for a CXL Type 1 device
 * @region: The CXL cache region to track
 * @hostmem_mr: The host memory region backing this cache
 *
 * Returns: Initialized coherency state, or NULL on failure
 */
CXLCacheCoherencyState *cxl_cache_coherency_init(CXLCacheRegion *region,
                                                   MemoryRegion *hostmem_mr);

/**
 * cxl_cache_coherency_cleanup - Clean up cache coherency state
 * @state: The coherency state to clean up
 *
 * This writes back all cached data and frees resources
 */
void cxl_cache_coherency_cleanup(CXLCacheCoherencyState *state);

/**
 * cxl_cache_mark_exclusive - Mark a cacheline as exclusive-able by the device
 * @state: The coherency state
 * @addr: Address of the cacheline
 * @ats_flags: ATS flags for this cacheline
 *
 * This allows the CXL device to take exclusive access to the cacheline.
 * A backup is created so recovery is possible if the device fails.
 */
void cxl_cache_mark_exclusive(CXLCacheCoherencyState *state, hwaddr addr,
                               uint32_t ats_flags);

/**
 * cxl_cache_release_exclusive - Release exclusive access to a cacheline
 * @state: The coherency state
 * @addr: Address of the cacheline
 *
 * This writes back the cacheline data and transitions to Invalid state.
 */
void cxl_cache_release_exclusive(CXLCacheCoherencyState *state, hwaddr addr);

/**
 * cxl_cache_device_offline - Handle device going offline
 * @state: The coherency state
 *
 * This is called when the device is hot-unplugged or fails.
 * All exclusive cachelines are restored from backup.
 */
void cxl_cache_device_offline(CXLCacheCoherencyState *state);

/**
 * cxl_cache_device_online - Handle device coming online
 * @state: The coherency state
 *
 * This is called when the device is hot-plugged or recovered.
 */
void cxl_cache_device_online(CXLCacheCoherencyState *state);

#endif /* CXL_CACHE_COHERENCY_H */
