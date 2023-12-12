/*
 * QEMU CXL Support
 *
 * Copyright (c) 2020 Intel
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See the
 * COPYING file in the top-level directory.
 */

#ifndef CXL_H
#define CXL_H


#include "qapi/qapi-types-machine.h"
#include "qapi/qapi-visit-machine.h"
#include "hw/pci/pci_host.h"
#include "cxl_pci.h"
#include "cxl_component.h"
#include "cxl_device.h"

#define CXL_COMPONENT_REG_BAR_IDX 0
#define CXL_DEVICE_REG_BAR_IDX 2

#define CXL_WINDOW_MAX 10

typedef struct PXBDev PXBDev;

typedef struct CXLCacheD2HReq {
    uint8_t data[8];
} CXLCacheD2HReq;

enum CXLCacheState{
    M,
    E,
    S,
    I
};

typedef struct CXLCache {
    uint8_t data[64];
    enum CXLCacheState state;
    uint32_t ats;
    CXLCacheD2HReq req[6];
    uint16_t remaining1;
    uint8_t remaining2;
    bool remaining3[3];
} CXLCache;
static_assert(sizeof(CXLCache) == 128, "CXLCache size is incorrect");

struct CXLCacheRegion {
    uint64_t size;
    char **targets;
    PXBDev *target_hbs[8];
    uint8_t num_targets;
    CXLCache *cache;
    hwaddr base;
};

typedef struct CXLFixedWindow {
    uint64_t size;
    char **targets;
    PXBDev *target_hbs[8];
    uint8_t num_targets;
    uint8_t enc_int_ways;
    uint8_t enc_int_gran;
    /* Todo: XOR based interleaving */
    MemoryRegion mr;
    hwaddr base;
} CXLFixedWindow;

typedef struct CXLState {
  bool is_enabled;
  MemoryRegion host_mr;
  unsigned int next_mr_idx;
  GList *fixed_windows;
  CXLFixedMemoryWindowOptionsList *cfmw_list;
  
  GList *ctype1s;
  CXLType1OptionsList *ctype1_list;
} CXLState;

struct CXLHost {
    PCIHostState parent_obj;

    CXLComponentState cxl_cstate;
    bool passthrough;
};

#define TYPE_PXB_CXL_HOST "pxb-cxl-host"
OBJECT_DECLARE_SIMPLE_TYPE(CXLHost, PXB_CXL_HOST)

#define TYPE_CXL_USP "cxl-upstream"

typedef struct CXLUpstreamPort CXLUpstreamPort;
DECLARE_INSTANCE_CHECKER(CXLUpstreamPort, CXL_USP, TYPE_CXL_USP)
CXLComponentState *cxl_usp_to_cstate(CXLUpstreamPort *usp);
#endif
