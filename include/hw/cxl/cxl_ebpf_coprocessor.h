/*
 * CXL eBPF Coprocessor Header
 *
 * Copyright (c) 2025 Drywall Project
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#ifndef CXL_EBPF_COPROCESSOR_H
#define CXL_EBPF_COPROCESSOR_H

#include "qemu/osdep.h"
#include "exec/hwaddr.h"

typedef struct CXLeBPFCoprocessor CXLeBPFCoprocessor;

struct CryptoProof;

/*
 * Initialize eBPF coprocessor
 */
CXLeBPFCoprocessor *cxl_ebpf_coprocessor_init(uint32_t device_id);

/*
 * Firewall check before granting exclusive access
 */
int cxl_ebpf_firewall_check(CXLeBPFCoprocessor *coproc,
                             uint64_t addr, bool is_write);

/*
 * Register shadow in device-private DRAM
 */
int cxl_ebpf_register_shadow(CXLeBPFCoprocessor *coproc,
                              uint64_t addr, const uint8_t *data);

/*
 * Generate cryptographic proof
 */
int cxl_ebpf_generate_proof(CXLeBPFCoprocessor *coproc,
                             uint64_t addr,
                             const uint8_t *old_data,
                             const uint8_t *new_data,
                             struct CryptoProof *proof_out);

/*
 * Validate cryptographic proof
 */
int cxl_ebpf_validate_proof(CXLeBPFCoprocessor *coproc,
                             const struct CryptoProof *proof);

/*
 * Hook: Called when exclusive access is granted
 */
void cxl_ebpf_on_exclusive_granted(CXLeBPFCoprocessor *coproc,
                                    hwaddr addr,
                                    const uint8_t *cacheline_data);

/*
 * Hook: Called when device attempts writeback
 * Returns true if commit allowed, false to deny and quarantine
 */
bool cxl_ebpf_on_writeback_request(CXLeBPFCoprocessor *coproc,
                                     hwaddr addr,
                                     const uint8_t *old_data,
                                     const uint8_t *new_data);

/*
 * Cleanup
 */
void cxl_ebpf_coprocessor_cleanup(CXLeBPFCoprocessor *coproc);

#endif /* CXL_EBPF_COPROCESSOR_H */
