/*
 * CXL Fault Injection Framework
 *
 * This module provides comprehensive fault injection capabilities for
 * CXL Type-1 devices to enable kernel fuzzing and robustness testing.
 * Integrated with the CXL firewall eBPF coprocessor.
 *
 * Copyright (c) 2025 Drywall Project
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See the
 * COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_device.h"
#include "hw/cxl/cxl_cache_coherency.h"
#include "cxl-fault-injection.h"
#include "ebpf/cxl_firewall.h"

#include <stdlib.h>

#define CACHELINE_SIZE 64
#define REVOKE_TIMEOUT_DEFAULT_NS (100 * 1000)  /* 100 microseconds */

/* Fault injection state per device */
struct CXLFaultInjectionState {
    CXLType1Dev *device;
    CXLFirewallState *firewall;

    /* Configuration */
    bool enabled;
    CXLFaultScenario current_scenario;
    uint32_t fault_probability;  /* 0-100 percentage */

    /* Delayed revoke tracking */
    uint64_t revoke_delay_ns;
    QEMUTimer *revoke_timeout_timer;
    uint64_t pending_revoke_addr;
    bool revoke_pending;

    /* Hot-unplug simulation */
    bool device_unplugged;
    QEMUTimer *unplug_timer;

    /* Statistics */
    uint64_t faults_triggered;
    uint64_t delayed_revokes;
    uint64_t dropped_transactions;
    uint64_t corrupted_cachelines;
    uint64_t state_violations;
};

/* Global fault injection instances (indexed by device ID) */
static CXLFaultInjectionState *g_fault_states[256] = {0};

/* Random number generator for probabilistic faults */
static inline bool should_inject_fault(uint32_t probability)
{
    if (probability == 0)
        return false;
    if (probability >= 100)
        return true;

    return (rand() % 100) < probability;
}

/* Revoke timeout handler - simulates device not responding within deadline */
static void revoke_timeout_handler(void *opaque)
{
    CXLFaultInjectionState *state = opaque;

    qemu_log_mask(LOG_GUEST_ERROR,
                  "CXL fault injection: Revoke timeout for addr 0x%lx "
                  "(device not responding)\n",
                  state->pending_revoke_addr);

    state->faults_triggered++;
    state->delayed_revokes++;

    /* Trigger shadow restore through firewall */
    if (state->firewall) {
        uint8_t shadow_data[CACHELINE_SIZE];

        if (cxl_firewall_restore_from_shadow(state->firewall,
                                             state->pending_revoke_addr,
                                             shadow_data,
                                             CACHELINE_SIZE) == 0) {
            info_report("CXL fault injection: Successfully restored cacheline "
                       "from shadow after revoke timeout");
        } else {
            error_report("CXL fault injection: Failed to restore cacheline "
                        "from shadow - system may be corrupted!");
        }
    }

    state->revoke_pending = false;
}

/* Hot-unplug timer handler */
static void hot_unplug_handler(void *opaque)
{
    CXLFaultInjectionState *state = opaque;

    info_report("CXL fault injection: Simulating device hot-unplug");

    state->device_unplugged = true;
    state->faults_triggered++;

    /* Notify coherency layer of device offline */
    if (state->device && state->device->coherency_state) {
        cxl_cache_device_offline(state->device->coherency_state);
    }

    /* Notify firewall */
    if (state->firewall) {
        cxl_firewall_device_offline(state->firewall, 0);  /* Device ID 0 */
    }
}

/* Initialize fault injection for a CXL Type-1 device */
CXLFaultInjectionState *cxl_fault_injection_init(CXLType1Dev *device,
                                                  Error **errp)
{
    CXLFaultInjectionState *state;

    state = g_new0(CXLFaultInjectionState, 1);

    state->device = device;
    state->firewall = cxl_firewall_get_global();
    state->enabled = false;
    state->current_scenario = CXL_FAULT_SCENARIO_NONE;
    state->fault_probability = 0;
    state->revoke_delay_ns = REVOKE_TIMEOUT_DEFAULT_NS * 2;  /* 2x normal timeout */
    state->device_unplugged = false;
    state->revoke_pending = false;

    /* Create timers */
    state->revoke_timeout_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                               revoke_timeout_handler, state);
    state->unplug_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                       hot_unplug_handler, state);

    /* Store in global array (using device ID 0 for now) */
    g_fault_states[0] = state;

    info_report("CXL fault injection initialized for device");

    return state;
}

/* Cleanup fault injection state */
void cxl_fault_injection_cleanup(CXLFaultInjectionState *state)
{
    if (!state)
        return;

    if (state->revoke_timeout_timer) {
        timer_free(state->revoke_timeout_timer);
    }

    if (state->unplug_timer) {
        timer_free(state->unplug_timer);
    }

    /* Remove from global array */
    for (int i = 0; i < 256; i++) {
        if (g_fault_states[i] == state) {
            g_fault_states[i] = NULL;
            break;
        }
    }

    g_free(state);
}

/* Configure fault injection scenario */
void cxl_fault_injection_set_scenario(CXLFaultInjectionState *state,
                                      CXLFaultScenario scenario,
                                      uint32_t probability)
{
    if (!state)
        return;

    state->current_scenario = scenario;
    state->fault_probability = probability;

    info_report("CXL fault injection: Configured scenario %d with %d%% probability",
                scenario, probability);

    /* Configure firewall eBPF for fault injection */
    if (state->firewall) {
        uint32_t ebpf_fault_type = CXL_FAULT_NONE;

        switch (scenario) {
        case CXL_FAULT_SCENARIO_DELAYED_REVOKE:
            ebpf_fault_type = CXL_FAULT_DELAYED_REVOKE;
            break;
        case CXL_FAULT_SCENARIO_SILENT_DROP:
            ebpf_fault_type = CXL_FAULT_SILENT_DROP;
            break;
        case CXL_FAULT_SCENARIO_CORRUPT_DATA:
            ebpf_fault_type = CXL_FAULT_CORRUPT_DATA;
            break;
        case CXL_FAULT_SCENARIO_STATE_VIOLATION:
            ebpf_fault_type = CXL_FAULT_STATE_VIOLATION;
            break;
        case CXL_FAULT_SCENARIO_HOT_UNPLUG:
            ebpf_fault_type = CXL_FAULT_HOT_UNPLUG;
            break;
        default:
            ebpf_fault_type = CXL_FAULT_NONE;
            break;
        }

        cxl_firewall_configure_fault_injection(state->firewall,
                                               scenario != CXL_FAULT_SCENARIO_NONE,
                                               (100 / (probability ? probability : 1)),
                                               ebpf_fault_type,
                                               0,  /* All devices */
                                               0, 0);  /* All addresses */
    }
}

/* Enable/disable fault injection */
void cxl_fault_injection_enable(CXLFaultInjectionState *state, bool enable)
{
    if (!state)
        return;

    state->enabled = enable;

    info_report("CXL fault injection: %s", enable ? "enabled" : "disabled");
}

/* Inject fault on cacheline read (exclusive access request) */
bool cxl_fault_inject_on_read_exclusive(CXLFaultInjectionState *state,
                                        uint64_t addr, uint32_t ats_flags,
                                        uint8_t *data)
{
    if (!state || !state->enabled || state->device_unplugged)
        return false;

    if (!should_inject_fault(state->fault_probability))
        return false;

    switch (state->current_scenario) {
    case CXL_FAULT_SCENARIO_SILENT_DROP:
        qemu_log_mask(LOG_GUEST_ERROR,
                     "CXL fault injection: Dropping exclusive read for addr 0x%lx\n",
                     addr);
        state->faults_triggered++;
        state->dropped_transactions++;
        return true;  /* Drop the transaction */

    case CXL_FAULT_SCENARIO_STATE_VIOLATION:
        qemu_log_mask(LOG_GUEST_ERROR,
                     "CXL fault injection: Forcing invalid state transition "
                     "for addr 0x%lx\n", addr);
        state->faults_triggered++;
        state->state_violations++;
        /* Force invalid state by corrupting ATS flags */
        /* This is handled by the caller */
        return false;

    case CXL_FAULT_SCENARIO_HOT_UNPLUG:
        /* Schedule hot-unplug after a short delay */
        if (!timer_pending(state->unplug_timer)) {
            uint64_t unplug_delay = 1000000;  /* 1ms */
            timer_mod(state->unplug_timer,
                     qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + unplug_delay);
            qemu_log_mask(LOG_GUEST_ERROR,
                         "CXL fault injection: Scheduled hot-unplug in %lu ns\n",
                         unplug_delay);
        }
        return false;

    default:
        return false;
    }
}

/* Inject fault on revoke request */
bool cxl_fault_inject_on_revoke(CXLFaultInjectionState *state, uint64_t addr)
{
    if (!state || !state->enabled || state->device_unplugged)
        return false;

    if (!should_inject_fault(state->fault_probability))
        return false;

    switch (state->current_scenario) {
    case CXL_FAULT_SCENARIO_DELAYED_REVOKE:
        qemu_log_mask(LOG_GUEST_ERROR,
                     "CXL fault injection: Delaying revoke response for addr 0x%lx "
                     "by %lu ns\n", addr, state->revoke_delay_ns);

        /* Set up delayed response */
        state->pending_revoke_addr = addr;
        state->revoke_pending = true;

        /* Start timeout timer */
        timer_mod(state->revoke_timeout_timer,
                 qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + state->revoke_delay_ns);

        state->faults_triggered++;
        return true;  /* Delay the revoke */

    case CXL_FAULT_SCENARIO_SILENT_DROP:
        qemu_log_mask(LOG_GUEST_ERROR,
                     "CXL fault injection: Dropping revoke request for addr 0x%lx\n",
                     addr);
        state->faults_triggered++;
        state->dropped_transactions++;
        return true;  /* Drop the revoke */

    default:
        return false;
    }
}

/* Inject fault on writeback */
bool cxl_fault_inject_on_writeback(CXLFaultInjectionState *state, uint64_t addr,
                                   uint8_t *data, size_t len)
{
    if (!state || !state->enabled || state->device_unplugged)
        return false;

    if (!should_inject_fault(state->fault_probability))
        return false;

    switch (state->current_scenario) {
    case CXL_FAULT_SCENARIO_CORRUPT_DATA:
        qemu_log_mask(LOG_GUEST_ERROR,
                     "CXL fault injection: Corrupting cacheline data for addr 0x%lx\n",
                     addr);

        /* Corrupt random bytes in the cacheline */
        for (size_t i = 0; i < len && i < CACHELINE_SIZE; i += 8) {
            if (should_inject_fault(50)) {  /* 50% chance per 8-byte chunk */
                uint64_t *ptr = (uint64_t *)(data + i);
                *ptr ^= 0xDEADBEEFCAFEBABEULL;  /* XOR with pattern */
            }
        }

        state->faults_triggered++;
        state->corrupted_cachelines++;
        return false;  /* Don't drop, but data is corrupted */

    case CXL_FAULT_SCENARIO_SILENT_DROP:
        qemu_log_mask(LOG_GUEST_ERROR,
                     "CXL fault injection: Dropping writeback for addr 0x%lx\n",
                     addr);
        state->faults_triggered++;
        state->dropped_transactions++;
        return true;  /* Drop the writeback */

    default:
        return false;
    }
}

/* Check if device is currently unplugged */
bool cxl_fault_injection_is_unplugged(CXLFaultInjectionState *state)
{
    return state ? state->device_unplugged : false;
}

/* Get fault injection statistics */
void cxl_fault_injection_get_stats(CXLFaultInjectionState *state,
                                   CXLFaultInjectionStats *stats)
{
    if (!state || !stats)
        return;

    stats->faults_triggered = state->faults_triggered;
    stats->delayed_revokes = state->delayed_revokes;
    stats->dropped_transactions = state->dropped_transactions;
    stats->corrupted_cachelines = state->corrupted_cachelines;
    stats->state_violations = state->state_violations;
    stats->device_unplugged = state->device_unplugged;
}

/* Reset statistics */
void cxl_fault_injection_reset_stats(CXLFaultInjectionState *state)
{
    if (!state)
        return;

    state->faults_triggered = 0;
    state->delayed_revokes = 0;
    state->dropped_transactions = 0;
    state->corrupted_cachelines = 0;
    state->state_violations = 0;
}

/* Trigger immediate hot-unplug */
void cxl_fault_injection_trigger_unplug(CXLFaultInjectionState *state)
{
    if (!state || state->device_unplugged)
        return;

    hot_unplug_handler(state);
}

/* Restore device from unplugged state (simulates hot-plug) */
void cxl_fault_injection_restore_device(CXLFaultInjectionState *state)
{
    if (!state || !state->device_unplugged)
        return;

    info_report("CXL fault injection: Restoring device from unplugged state");

    state->device_unplugged = false;

    /* Notify coherency layer of device online */
    if (state->device && state->device->coherency_state) {
        cxl_cache_device_online(state->device->coherency_state);
    }
}
