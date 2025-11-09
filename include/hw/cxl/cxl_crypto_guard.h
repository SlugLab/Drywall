/*
 * CXL Type 1 Crypto Guard Extension
 *
 * This extends the CXL Type 1 cache coherency implementation with crypto
 * metadata detection and shadow-before-exclusivity enforcement for LUKS/dm-crypt
 * protection.
 *
 * Implements the flowchart:
 * 1. Policy check (ATS/PASID + per-page exclusivity)
 * 2. Shadow installation before granting E/M access
 * 3. Device update with local proof (eBPF coprocessor)
 * 4. Timeout/policy violation detection
 * 5. Proof validation and commit/quarantine
 * 6. Recovery with authoritative state reconstruction
 *
 * Copyright (c) 2025 Drywall Project
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.
 */

#ifndef CXL_CRYPTO_GUARD_H
#define CXL_CRYPTO_GUARD_H

#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_cache_coherency.h"
#include "exec/memory.h"
#include "qemu/timer.h"

/* Crypto metadata region types (detected from access patterns) */
#define CRYPTO_REGION_LUKS_HEADER     0x01  /* LUKS header (key slots, config) */
#define CRYPTO_REGION_IV_COUNTER      0x02  /* IV generation counters */
#define CRYPTO_REGION_INTEGRITY_TAG   0x04  /* Journaled integrity tags */
#define CRYPTO_REGION_CRYPTO_CTX      0x08  /* Crypto context (keys, state) */
#define CRYPTO_REGION_KEY_MATERIAL    0x10  /* Active key material in memory */
#define CRYPTO_REGION_DMCRYPT_STATE   0x20  /* dm-crypt driver state */

/* Protection levels (policy enforcement modes) */
#define PROTECTION_NONE               0  /* No protection - grant normally */
#define PROTECTION_DENY_EXCLUSIVE     1  /* Deny E/M, grant S only */
#define PROTECTION_SHADOW_REQUIRED    2  /* Shadow-before-exclusivity */
#define PROTECTION_READ_ONLY          3  /* Read-only, deny writes */
#define PROTECTION_COMPLETE_DENY      4  /* No CXL access allowed */

/* Policy decision results */
typedef enum {
    POLICY_ALLOW_EXCLUSIVE,      /* Grant E/M access with shadow */
    POLICY_DENY_EXCLUSIVE,       /* Deny E/M, grant S or bounce */
    POLICY_QUARANTINE,           /* Device quarantined, deny all */
} CryptoPolicyDecision;

/* Proof validation results */
typedef enum {
    PROOF_VALID,                 /* Proof validates, commit changes */
    PROOF_INVALID,               /* Proof failed, quarantine + rollback */
    PROOF_TIMEOUT,               /* Timeout, revoke and recover */
} ProofValidationResult;

/* Shadow entry state
 *
 * IMPORTANT: Shadow data is stored in DEVICE-PRIVATE DRAM, NOT host memory.
 * This ensures that shadows survive host memory corruption and are isolated
 * from potential adversarial access patterns.
 *
 * In a real Type 1 device implementation, shadow_data would be a pointer/offset
 * into the device's local DRAM (e.g., FPGA BRAM, ASIC SRAM, or dedicated shadow cache).
 * For QEMU emulation, we allocate it here but conceptually it lives in the device.
 */
typedef struct CXLCryptoGuardState CXLCryptoGuardState;

typedef struct CryptoShadowEntry {
    hwaddr addr;                 /* Cacheline address */
    uint64_t epoch;              /* Shadow creation timestamp */
    uint32_t device_id;          /* Owner device (PASID/BDF) */
    uint32_t region_type;        /* Detected crypto region type */

    /* Shadow data (64-byte cacheline) - STORED IN DEVICE-PRIVATE DRAM */
    uint8_t shadow_data[64];
    uint64_t shadow_hash;        /* Hash of shadow data */

    /* Proof metadata from eBPF coprocessor */
    uint8_t proof_data[128];     /* Device-generated proof */
    uint64_t proof_timestamp;    /* When proof was generated */

    /* Watchdog and scheduling */
    QEMUTimer *watchdog;         /* Timeout for exclusive access */
    uint64_t timeout_ns;         /* Timeout duration (host-biased) */

    /* State tracking */
    bool exclusive_granted;      /* Is device holding E/M? */
    bool proof_validated;        /* Has proof been validated? */
    bool quarantined;            /* Is this entry quarantined? */

    /* Back-pointer to parent state for timeout handler */
    CXLCryptoGuardState *parent_state;

    QLIST_ENTRY(CryptoShadowEntry) next;
} CryptoShadowEntry;

/* Crypto guard state for a CXL Type 1 device */
typedef struct CXLCryptoGuardState {
    /* Underlying cache coherency state */
    CXLCacheCoherencyState *cache_state;

    /* Shadow entry tracking */
    QLIST_HEAD(, CryptoShadowEntry) shadow_entries;
    QemuMutex shadow_lock;

    /* Policy configuration */
    uint32_t default_protection_level;
    bool auto_detect_crypto_regions;
    uint64_t default_timeout_ns;     /* Default watchdog timeout */

    /* Statistics and audit log */
    uint64_t total_accesses;
    uint64_t shadows_created;
    uint64_t shadows_committed;
    uint64_t policy_denials;
    uint64_t timeouts;
    uint64_t proof_failures;
    uint64_t recoveries;

    /* Quarantine tracking */
    uint32_t quarantined_devices[256];  /* Bitmap of quarantined device IDs */

    /* Device online/offline state */
    bool device_online;

} CXLCryptoGuardState;

/**
 * cxl_crypto_guard_init - Initialize crypto guard for a CXL Type 1 device
 * @cache_state: The underlying cache coherency state
 * @default_protection: Default protection level for detected crypto regions
 *
 * Returns: Initialized crypto guard state, or NULL on failure
 */
CXLCryptoGuardState *cxl_crypto_guard_init(CXLCacheCoherencyState *cache_state,
                                            uint32_t default_protection);

/**
 * cxl_crypto_guard_cleanup - Clean up crypto guard state
 * @state: The crypto guard state to clean up
 */
void cxl_crypto_guard_cleanup(CXLCryptoGuardState *state);

/**
 * cxl_crypto_guard_check_policy - Check if device can get exclusive access
 * @state: The crypto guard state
 * @addr: Address of the cacheline being requested
 * @device_id: Device identifier (PASID/BDF)
 * @ats_flags: ATS flags for this access
 *
 * Implements: "Policy check" from flowchart
 * Checks: ATS/PASID + per-page exclusivity mask → modes
 *
 * Returns: Policy decision (ALLOW/DENY/QUARANTINE)
 */
CryptoPolicyDecision cxl_crypto_guard_check_policy(CXLCryptoGuardState *state,
                                                     hwaddr addr,
                                                     uint32_t device_id,
                                                     uint32_t ats_flags);

/**
 * cxl_crypto_guard_install_shadow - Install shadow and grant exclusive access
 * @state: The crypto guard state
 * @addr: Address of the cacheline
 * @device_id: Device identifier (PASID/BDF)
 * @data: Current cacheline data to shadow
 *
 * Implements: "Install shadow & grant" from flowchart
 * Creates shadow entry in device-private DRAM
 * Encodes {epoch, owner, hash}; arms watchdog; host-biased scheduling
 *
 * Returns: 0 on success, -1 on failure
 */
int cxl_crypto_guard_install_shadow(CXLCryptoGuardState *state,
                                     hwaddr addr,
                                     uint32_t device_id,
                                     const uint8_t *data);

/**
 * cxl_crypto_guard_device_update - Device updates cacheline with proof
 * @state: The crypto guard state
 * @addr: Address of the cacheline
 * @device_id: Device identifier
 * @new_data: Updated data from device
 * @proof: Proof data from eBPF coprocessor
 * @proof_len: Length of proof data
 *
 * Implements: "Device update + local proof" from flowchart
 * Device mutates shadowed line; generates proof via eBPF coprocessor
 * Host collects metadata for later validation
 *
 * Returns: 0 on success, -1 on failure
 */
int cxl_crypto_guard_device_update(CXLCryptoGuardState *state,
                                    hwaddr addr,
                                    uint32_t device_id,
                                    const uint8_t *new_data,
                                    const uint8_t *proof,
                                    size_t proof_len);

/**
 * cxl_crypto_guard_validate_proof - Validate device proof and commit/quarantine
 * @state: The crypto guard state
 * @addr: Address of the cacheline
 *
 * Implements: "Proof validates?" decision from flowchart
 * If valid: "Commit" - Apply to kernel state; release ownership; append journal
 * If invalid: "Quarantine & rollback" - Quarantine region/PASID; rollback from shadow
 *
 * Returns: Proof validation result
 */
ProofValidationResult cxl_crypto_guard_validate_proof(CXLCryptoGuardState *state,
                                                        hwaddr addr);

/**
 * cxl_crypto_guard_timeout_handler - Handle timeout/policy violation
 * @addr: Address of the timed-out cacheline
 *
 * Implements: "Revoke / degrade" → "Recover authoritative state" → "Resume host progress"
 * - Force writeback; fence PASID/region
 * - Blacklist or throttle offender
 * - Reconstruct from shadow + host log
 * - Mark device as suspect
 * - Host-owned update; audit
 */
void cxl_crypto_guard_timeout_handler(void *opaque);

/**
 * cxl_crypto_guard_revoke_exclusive - Revoke exclusive access and recover
 * @state: The crypto guard state
 * @addr: Address of the cacheline
 *
 * Implements: "Revoke / degrade" from flowchart
 * Force writeback; fence PASID/region; blacklist or throttle offender
 */
void cxl_crypto_guard_revoke_exclusive(CXLCryptoGuardState *state, hwaddr addr);

/**
 * cxl_crypto_guard_recover_state - Recover authoritative state from shadow
 * @state: The crypto guard state
 * @addr: Address of the cacheline
 *
 * Implements: "Recover authoritative state" from flowchart
 * Reconstruct from shadow + host log; mark device as suspect
 *
 * Returns: 0 on success, -1 on failure
 */
int cxl_crypto_guard_recover_state(CXLCryptoGuardState *state, hwaddr addr);

/**
 * cxl_crypto_guard_commit_update - Commit validated update to kernel state
 * @state: The crypto guard state
 * @addr: Address of the cacheline
 *
 * Implements: "Commit" from flowchart
 * Apply to kernel state; release ownership; append journal
 */
void cxl_crypto_guard_commit_update(CXLCryptoGuardState *state, hwaddr addr);

/**
 * cxl_crypto_guard_quarantine - Quarantine device and rollback
 * @state: The crypto guard state
 * @addr: Address of the cacheline
 * @device_id: Device to quarantine
 *
 * Implements: "Quarantine & rollback" from flowchart
 * Quarantine region/PASID; rollback from shadow; alert & rate-limit
 */
void cxl_crypto_guard_quarantine(CXLCryptoGuardState *state,
                                  hwaddr addr,
                                  uint32_t device_id);

/**
 * cxl_crypto_guard_detect_crypto_region - Auto-detect crypto metadata region
 * @state: The crypto guard state
 * @addr: Address being accessed
 * @data: Data at this address
 *
 * Heuristically detects LUKS headers, IV counters, crypto contexts, etc.
 *
 * Returns: Detected region type flags, or 0 if not crypto-related
 */
uint32_t cxl_crypto_guard_detect_crypto_region(CXLCryptoGuardState *state,
                                                 hwaddr addr,
                                                 const uint8_t *data);

/**
 * cxl_crypto_guard_device_offline - Handle device offline (fault/hot-unplug)
 * @state: The crypto guard state
 *
 * Revokes all exclusive accesses and recovers from shadows
 */
void cxl_crypto_guard_device_offline(CXLCryptoGuardState *state);

/**
 * cxl_crypto_guard_device_online - Handle device coming online
 * @state: The crypto guard state
 */
void cxl_crypto_guard_device_online(CXLCryptoGuardState *state);

/**
 * cxl_crypto_guard_get_stats - Get crypto guard statistics
 * @state: The crypto guard state
 * @stats_out: Output buffer for statistics
 */
void cxl_crypto_guard_get_stats(CXLCryptoGuardState *state, void *stats_out);

#endif /* CXL_CRYPTO_GUARD_H */
