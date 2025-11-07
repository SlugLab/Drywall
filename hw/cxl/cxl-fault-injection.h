/*
 * CXL Fault Injection Header
 *
 * Copyright (c) 2025 Drywall Project
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#ifndef CXL_FAULT_INJECTION_H
#define CXL_FAULT_INJECTION_H

#include "qemu/osdep.h"

/* Forward declarations */
typedef struct CXLFaultInjectionState CXLFaultInjectionState;
typedef struct CXLType1Dev CXLType1Dev;
typedef struct Error Error;

/* Fault scenarios for testing */
typedef enum CXLFaultScenario {
    CXL_FAULT_SCENARIO_NONE = 0,
    CXL_FAULT_SCENARIO_DELAYED_REVOKE = 1,     /* Device delays revoke response */
    CXL_FAULT_SCENARIO_SILENT_DROP = 2,        /* Device drops transactions */
    CXL_FAULT_SCENARIO_CORRUPT_DATA = 3,       /* Device corrupts cacheline data */
    CXL_FAULT_SCENARIO_STATE_VIOLATION = 4,    /* Invalid coherence state transition */
    CXL_FAULT_SCENARIO_HOT_UNPLUG = 5,        /* Device hot-unplug during operation */
    CXL_FAULT_SCENARIO_MAX
} CXLFaultScenario;

/* Statistics for fault injection */
typedef struct CXLFaultInjectionStats {
    uint64_t faults_triggered;
    uint64_t delayed_revokes;
    uint64_t dropped_transactions;
    uint64_t corrupted_cachelines;
    uint64_t state_violations;
    bool device_unplugged;
} CXLFaultInjectionStats;

/* Initialize fault injection for a device */
CXLFaultInjectionState *cxl_fault_injection_init(CXLType1Dev *device,
                                                  Error **errp);

/* Cleanup fault injection */
void cxl_fault_injection_cleanup(CXLFaultInjectionState *state);

/* Configure fault injection scenario */
void cxl_fault_injection_set_scenario(CXLFaultInjectionState *state,
                                      CXLFaultScenario scenario,
                                      uint32_t probability);

/* Enable/disable fault injection */
void cxl_fault_injection_enable(CXLFaultInjectionState *state, bool enable);

/* Fault injection hooks for different operations */
bool cxl_fault_inject_on_read_exclusive(CXLFaultInjectionState *state,
                                        uint64_t addr, uint32_t ats_flags,
                                        uint8_t *data);

bool cxl_fault_inject_on_revoke(CXLFaultInjectionState *state, uint64_t addr);

bool cxl_fault_inject_on_writeback(CXLFaultInjectionState *state, uint64_t addr,
                                   uint8_t *data, size_t len);

/* Device state queries */
bool cxl_fault_injection_is_unplugged(CXLFaultInjectionState *state);

/* Statistics and control */
void cxl_fault_injection_get_stats(CXLFaultInjectionState *state,
                                   CXLFaultInjectionStats *stats);

void cxl_fault_injection_reset_stats(CXLFaultInjectionState *state);

/* Manual triggers */
void cxl_fault_injection_trigger_unplug(CXLFaultInjectionState *state);
void cxl_fault_injection_restore_device(CXLFaultInjectionState *state);

#endif /* CXL_FAULT_INJECTION_H */
