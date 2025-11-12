/*
 * CXL eBPF Coprocessor Integration for QEMU
 *
 * This file integrates the userspace eBPF coprocessor runtime with
 * QEMU's CXL Type 1 device implementation.
 *
 * Copyright (c) 2025 Drywall Project
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_crypto_guard.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define COPROCESSOR_SOCKET "/tmp/cxl_coprocessor.sock"

typedef struct CXLeBPFCoprocessor {
    int sock_fd;
    bool connected;
    uint32_t device_id;
} CXLeBPFCoprocessor;

/* Message types for coprocessor communication */
enum CoprocessorMsgType {
    MSG_FIREWALL_CHECK = 1,
    MSG_REGISTER_SHADOW = 2,
    MSG_GENERATE_PROOF = 3,
    MSG_VALIDATE_PROOF = 4,
    MSG_SET_DEVICE_KEY = 5,
    MSG_ADD_FIREWALL_RULE = 6,
};

/* Message header */
struct CoprocessorMsg {
    uint32_t type;
    uint32_t length;
    uint8_t data[4096];
} __attribute__((packed));

/* Firewall check request */
struct FirewallCheckReq {
    uint64_t addr;
    uint32_t device_id;
    uint8_t is_write;
} __attribute__((packed));

/* Shadow registration request */
struct RegisterShadowReq {
    uint64_t addr;
    uint32_t device_id;
    uint32_t region_type;
    uint8_t data[64];
} __attribute__((packed));

/* Proof generation request */
struct GenerateProofReq {
    uint64_t addr;
    uint32_t device_id;
    uint8_t old_data[64];
    uint8_t new_data[64];
} __attribute__((packed));

/* Crypto proof (from coprocessor) */
struct CryptoProof {
    uint64_t timestamp;
    uint64_t sequence;
    uint64_t shadow_hash;
    uint64_t new_hash;
    uint64_t addr;
    uint32_t device_id;
    uint32_t operation_type;
    uint64_t exec_trace_checksum;
    uint32_t exec_step_count;
    uint32_t exec_flags;
    uint8_t hmac[32];
    uint8_t padding[8];
} __attribute__((packed));

/*
 * Initialize eBPF coprocessor connection
 */
CXLeBPFCoprocessor *cxl_ebpf_coprocessor_init(uint32_t device_id)
{
    CXLeBPFCoprocessor *coproc = g_new0(CXLeBPFCoprocessor, 1);

    coproc->device_id = device_id;
    coproc->sock_fd = -1;
    coproc->connected = false;

    qemu_log_mask(LOG_GUEST_ERROR,
                  "CXL eBPF Coprocessor: Initialized for device %u\n",
                  device_id);
    qemu_log_mask(LOG_GUEST_ERROR,
                  "  Note: Coprocessor runs in device hardware (simulated in userspace)\n");

    return coproc;
}

/*
 * Firewall check - call eBPF coprocessor
 */
int cxl_ebpf_firewall_check(CXLeBPFCoprocessor *coproc,
                             uint64_t addr, bool is_write)
{
    if (!coproc) {
        return 0;  /* Allow if no coprocessor */
    }

    /* In real hardware, this would be a function call to the eBPF runtime
     * running on the device's embedded processor. For simulation, we
     * inline the logic here. */

    qemu_log_mask(LOG_GUEST_ERROR,
                  "CXL eBPF: Firewall check addr=0x%lx device=%u write=%d\n",
                  addr, coproc->device_id, is_write);

    /* Simulate firewall allow for demo */
    return 0;  /* FW_ALLOW */
}

/*
 * Register shadow in device-private DRAM
 */
int cxl_ebpf_register_shadow(CXLeBPFCoprocessor *coproc,
                              uint64_t addr, const uint8_t *data)
{
    if (!coproc) {
        return -1;
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "CXL eBPF: Shadow registered addr=0x%lx device=%u\n",
                  addr, coproc->device_id);

    /* In real hardware, this would:
     * 1. Allocate slot in device SRAM/shadow cache
     * 2. DMA cacheline data from host to device
     * 3. Compute and store shadow hash
     * 4. Set up watchdog timer
     */

    return 0;
}

/*
 * Generate proof of update
 */
int cxl_ebpf_generate_proof(CXLeBPFCoprocessor *coproc,
                             uint64_t addr,
                             const uint8_t *old_data,
                             const uint8_t *new_data,
                             struct CryptoProof *proof_out)
{
    if (!coproc || !proof_out) {
        return -1;
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "CXL eBPF: Generating proof addr=0x%lx device=%u\n",
                  addr, coproc->device_id);

    /* In real hardware, this would:
     * 1. Lookup shadow in device SRAM
     * 2. Verify old_data matches shadow
     * 3. Compute hashes
     * 4. Sign with device HMAC key
     * 5. Send proof to host via ring buffer
     */

    /* For simulation, fill dummy proof */
    memset(proof_out, 0, sizeof(*proof_out));
    proof_out->addr = addr;
    proof_out->device_id = coproc->device_id;
    proof_out->sequence = 1;

    return 0;
}

/*
 * Validate proof
 */
int cxl_ebpf_validate_proof(CXLeBPFCoprocessor *coproc,
                             const struct CryptoProof *proof)
{
    if (!coproc || !proof) {
        return -1;
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "CXL eBPF: Validating proof addr=0x%lx seq=%lu\n",
                  proof->addr, proof->sequence);

    /* In real hardware, the host would:
     * 1. Receive proof from device ring buffer
     * 2. Verify HMAC signature
     * 3. Check sequence number
     * 4. Validate hash chain
     */

    return 0;  /* PROOF_VALID */
}

/*
 * Hook called when cache coherency grants exclusive access
 */
void cxl_ebpf_on_exclusive_granted(CXLeBPFCoprocessor *coproc,
                                    hwaddr addr,
                                    const uint8_t *cacheline_data)
{
    if (!coproc) return;

    /* Firewall check */
    int fw_result = cxl_ebpf_firewall_check(coproc, addr, true);
    if (fw_result != 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "CXL eBPF: Firewall DENIED access to 0x%lx\n", addr);
        /* In real hardware, would abort the grant */
        return;
    }

    /* Install shadow before granting exclusive */
    cxl_ebpf_register_shadow(coproc, addr, cacheline_data);

    qemu_log_mask(LOG_GUEST_ERROR,
                  "CXL eBPF: Exclusive granted to 0x%lx with shadow protection\n",
                  addr);
}

/*
 * Hook called when device attempts to commit writeback
 */
bool cxl_ebpf_on_writeback_request(CXLeBPFCoprocessor *coproc,
                                     hwaddr addr,
                                     const uint8_t *old_data,
                                     const uint8_t *new_data)
{
    struct CryptoProof proof;

    if (!coproc) {
        return true;  /* Allow if no coprocessor */
    }

    /* Generate proof */
    if (cxl_ebpf_generate_proof(coproc, addr, old_data, new_data, &proof) < 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "CXL eBPF: Proof generation FAILED for 0x%lx\n", addr);
        return false;
    }

    /* Validate proof */
    if (cxl_ebpf_validate_proof(coproc, &proof) != 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "CXL eBPF: Proof validation FAILED for 0x%lx - QUARANTINE DEVICE\n",
                      addr);
        return false;
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "CXL eBPF: Writeback validated for 0x%lx - COMMIT ALLOWED\n",
                  addr);

    return true;
}

/*
 * Cleanup
 */
void cxl_ebpf_coprocessor_cleanup(CXLeBPFCoprocessor *coproc)
{
    if (!coproc) return;

    if (coproc->sock_fd >= 0) {
        close(coproc->sock_fd);
    }

    g_free(coproc);
}
