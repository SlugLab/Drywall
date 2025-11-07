/*
 * CXL Firewall Header
 *
 * Copyright (c) 2025 Drywall Project
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#ifndef CXL_FIREWALL_H
#define CXL_FIREWALL_H

#include "qemu/osdep.h"

/* Forward declarations */
typedef struct CXLFirewallState CXLFirewallState;
typedef struct Error Error;

/* ATS policy flags */
#define ATS_POLICY_READ           (1 << 0)
#define ATS_POLICY_WRITE          (1 << 1)
#define ATS_POLICY_EXCLUSIVE      (1 << 2)
#define ATS_POLICY_PROTECTED      (1 << 3)

/* Fault injection types */
enum CXLFaultType {
    CXL_FAULT_NONE = 0,
    CXL_FAULT_DELAYED_REVOKE = 1,
    CXL_FAULT_SILENT_DROP = 2,
    CXL_FAULT_CORRUPT_DATA = 3,
    CXL_FAULT_STATE_VIOLATION = 4,
    CXL_FAULT_HOT_UNPLUG = 5,
};

/* Statistics structure */
typedef struct CXLFirewallStats {
    uint64_t total_transactions;
    uint64_t exclusive_grants;
    uint64_t exclusive_revokes;
    uint64_t policy_violations;
    uint64_t shadow_creates;
    uint64_t shadow_restores;
    uint64_t faults_injected;
} CXLFirewallStats;

/* Structures matching eBPF definitions */
struct shadow_cacheline {
    uint64_t addr;
    uint64_t timestamp;
    uint64_t version;
    uint32_t device_id;
    uint32_t ats_flags;
    uint8_t state;
    uint8_t data[64];
    uint8_t checksum[8];
} __attribute__((packed));

struct ats_policy {
    uint64_t start_addr;
    uint64_t end_addr;
    uint32_t policy_flags;
    uint32_t device_mask;
    uint8_t allow_exclusive;
    uint8_t require_shadow;
    uint8_t priority;
} __attribute__((packed));

struct fault_injection_config {
    uint32_t enabled;
    uint32_t inject_rate;
    uint32_t fault_type;
    uint32_t target_device;
    uint64_t target_addr_start;
    uint64_t target_addr_end;
} __attribute__((packed));

struct cxl_statistics {
    uint64_t total_transactions;
    uint64_t exclusive_grants;
    uint64_t exclusive_revokes;
    uint64_t policy_violations;
    uint64_t shadow_creates;
    uint64_t shadow_restores;
    uint64_t faults_injected;
    uint64_t state_transitions[4][4];
} __attribute__((packed));

/* Initialization and cleanup */
CXLFirewallState *cxl_firewall_init(Error **errp);
void cxl_firewall_cleanup(CXLFirewallState *state);

/* Policy management */
int cxl_firewall_add_policy(CXLFirewallState *state, uint64_t start_addr,
                            uint64_t end_addr, uint32_t policy_flags,
                            bool allow_exclusive, bool require_shadow);

/* Fault injection configuration */
int cxl_firewall_configure_fault_injection(CXLFirewallState *state,
                                           bool enabled, uint32_t inject_rate,
                                           uint32_t fault_type,
                                           uint32_t target_device,
                                           uint64_t target_addr_start,
                                           uint64_t target_addr_end);

/* Access control and shadow management */
bool cxl_firewall_check_exclusive_access(CXLFirewallState *state, uint64_t addr,
                                         uint32_t device_id, uint32_t ats_flags);

int cxl_firewall_create_shadow(CXLFirewallState *state, uint64_t addr,
                               uint32_t device_id, uint32_t ats_flags,
                               uint8_t *data, size_t len);

int cxl_firewall_restore_from_shadow(CXLFirewallState *state, uint64_t addr,
                                    uint8_t *data_out, size_t len);

/* Device event handling */
int cxl_firewall_device_offline(CXLFirewallState *state, uint32_t device_id);

/* Statistics */
int cxl_firewall_get_stats(CXLFirewallState *state, CXLFirewallStats *stats_out);

/* Global instance accessor */
CXLFirewallState *cxl_firewall_get_global(void);

#endif /* CXL_FIREWALL_H */
