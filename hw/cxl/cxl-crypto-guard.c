/*
 * CXL Type 1 Crypto Guard Implementation
 *
 * This implements the crypto guard extension for CXL Type 1 devices,
 * providing shadow-before-exclusivity enforcement for LUKS/dm-crypt
 * cryptographic metadata protection.
 *
 * Flowchart implementation:
 * START → Policy check → Install shadow & grant → Device update + proof →
 * Timeout check → Proof validation → Commit/Quarantine/Recover → END
 *
 * Copyright (c) 2025 Drywall Project
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_device.h"
#include "hw/cxl/cxl_cache_coherency.h"
#include "hw/cxl/cxl_crypto_guard.h"
#include "exec/memory.h"
#include "crypto/hash.h"

#define CRYPTO_GUARD_LOG_PREFIX "[CXL-Crypto-Guard] "

/* LUKS magic signature */
#define LUKS_MAGIC "LUKS\xba\xbe"
#define LUKS_MAGIC_LEN 6

/* Default timeout for exclusive access (100ms) */
#define DEFAULT_TIMEOUT_NS (100 * 1000 * 1000ULL)

/* Maximum shadow entries */
#define MAX_SHADOW_ENTRIES 4096

/* Helper: Compute simple hash for shadow data */
static uint64_t compute_shadow_hash(const uint8_t *data, size_t len)
{
    uint64_t hash = 0xcbf29ce484222325ULL; /* FNV-1a initial value */
    const uint64_t prime = 0x100000001b3ULL;

    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= prime;
    }

    return hash;
}

/* Helper: Find shadow entry by address */
static CryptoShadowEntry *find_shadow_entry(CXLCryptoGuardState *state, hwaddr addr)
{
    CryptoShadowEntry *entry;

    QLIST_FOREACH(entry, &state->shadow_entries, next) {
        if (entry->addr == addr) {
            return entry;
        }
    }

    return NULL;
}

/* Helper: Check if device is quarantined */
static bool is_device_quarantined(CXLCryptoGuardState *state, uint32_t device_id)
{
    if (device_id >= 256) {
        return false;
    }

    return (state->quarantined_devices[device_id / 32] & (1U << (device_id % 32))) != 0;
}

/* Helper: Quarantine a device */
static void quarantine_device(CXLCryptoGuardState *state, uint32_t device_id)
{
    if (device_id >= 256) {
        return;
    }

    state->quarantined_devices[device_id / 32] |= (1U << (device_id % 32));

    qemu_log_mask(LOG_GUEST_ERROR,
                  CRYPTO_GUARD_LOG_PREFIX "Device %u quarantined\n",
                  device_id);
}

/**
 * Auto-detect crypto metadata regions
 *
 * Heuristically detects:
 * - LUKS headers (magic signature)
 * - IV counters (monotonic increasing patterns)
 * - Crypto contexts (high entropy, aligned structures)
 */
uint32_t cxl_crypto_guard_detect_crypto_region(CXLCryptoGuardState *state,
                                                 hwaddr addr,
                                                 const uint8_t *data)
{
    uint32_t region_type = 0;

    if (!state || !data || !state->auto_detect_crypto_regions) {
        return 0;
    }

    /* Check for LUKS header magic */
    if (memcmp(data, LUKS_MAGIC, LUKS_MAGIC_LEN) == 0) {
        region_type |= CRYPTO_REGION_LUKS_HEADER;
        qemu_log_mask(LOG_GUEST_ERROR,
                      CRYPTO_GUARD_LOG_PREFIX "Detected LUKS header at 0x%lx\n",
                      addr);
    }

    /* Check for high-entropy data (potential key material) */
    int zero_count = 0;
    int ff_count = 0;
    for (int i = 0; i < 64; i++) {
        if (data[i] == 0x00) zero_count++;
        if (data[i] == 0xFF) ff_count++;
    }

    /* High entropy = not mostly zeros or FFs */
    if (zero_count < 10 && ff_count < 10) {
        /* Check alignment - crypto structures are usually aligned */
        if ((addr % 64) == 0) {
            region_type |= CRYPTO_REGION_CRYPTO_CTX;
        }
    }

    /* Check for monotonic counters (IV counters) */
    uint64_t *values = (uint64_t *)data;
    bool monotonic = true;
    for (int i = 1; i < 8 && monotonic; i++) {
        if (values[i] != 0 && values[i] <= values[i-1]) {
            monotonic = false;
        }
    }
    if (monotonic && values[0] != 0) {
        region_type |= CRYPTO_REGION_IV_COUNTER;
    }

    return region_type;
}

/**
 * Policy check - Decide if device can get exclusive access
 *
 * Flowchart: "Policy check" step
 * Inputs: ATS/PASID + per-page exclusivity mask
 * Outputs: ALLOW_EXCLUSIVE, DENY_EXCLUSIVE, or QUARANTINE
 */
CryptoPolicyDecision cxl_crypto_guard_check_policy(CXLCryptoGuardState *state,
                                                     hwaddr addr,
                                                     uint32_t device_id,
                                                     uint32_t ats_flags)
{
    uint32_t region_type;
    uint32_t protection_level;

    if (!state) {
        return POLICY_DENY_EXCLUSIVE;
    }

    /* Check if device is quarantined */
    if (is_device_quarantined(state, device_id)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      CRYPTO_GUARD_LOG_PREFIX "Access denied - device %u is quarantined\n",
                      device_id);
        return POLICY_QUARANTINE;
    }

    /* Check if we have an existing shadow entry */
    qemu_mutex_lock(&state->shadow_lock);
    CryptoShadowEntry *entry = find_shadow_entry(state, addr);
    qemu_mutex_unlock(&state->shadow_lock);

    /* If entry exists and is held by another device, deny */
    if (entry && entry->exclusive_granted && entry->device_id != device_id) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      CRYPTO_GUARD_LOG_PREFIX "Access denied - addr 0x%lx held by device %u\n",
                      addr, entry->device_id);
        state->policy_denials++;
        return POLICY_DENY_EXCLUSIVE;
    }

    /* Auto-detect crypto region type if enabled */
    region_type = entry ? entry->region_type : 0;
    if (region_type == 0 && state->auto_detect_crypto_regions) {
        uint8_t sample_data[64];
        /* In real implementation, would read from memory here */
        memset(sample_data, 0, sizeof(sample_data));
        region_type = cxl_crypto_guard_detect_crypto_region(state, addr, sample_data);
    }

    /* Determine protection level */
    protection_level = state->default_protection_level;

    /* Override for specific region types */
    if (region_type & CRYPTO_REGION_LUKS_HEADER) {
        protection_level = PROTECTION_SHADOW_REQUIRED;
    } else if (region_type & CRYPTO_REGION_IV_COUNTER) {
        protection_level = PROTECTION_SHADOW_REQUIRED;
    } else if (region_type & CRYPTO_REGION_KEY_MATERIAL) {
        protection_level = PROTECTION_COMPLETE_DENY;
    }

    /* Apply policy */
    switch (protection_level) {
    case PROTECTION_NONE:
        return POLICY_ALLOW_EXCLUSIVE;

    case PROTECTION_DENY_EXCLUSIVE:
        state->policy_denials++;
        return POLICY_DENY_EXCLUSIVE;

    case PROTECTION_SHADOW_REQUIRED:
        /* Allow if we can create shadow */
        return POLICY_ALLOW_EXCLUSIVE;

    case PROTECTION_READ_ONLY:
        /* Deny writes (check ATS flags) */
        if (ats_flags & 0x1) { /* Write bit */
            state->policy_denials++;
            return POLICY_DENY_EXCLUSIVE;
        }
        return POLICY_ALLOW_EXCLUSIVE;

    case PROTECTION_COMPLETE_DENY:
        state->policy_denials++;
        return POLICY_DENY_EXCLUSIVE;

    default:
        return POLICY_DENY_EXCLUSIVE;
    }
}

/**
 * Timeout handler for exclusive access watchdog
 *
 * Flowchart: "Timeout / policy violation detected?" → YES branch
 * Actions: Revoke → Recover → Resume host progress
 */
void cxl_crypto_guard_timeout_handler(void *opaque)
{
    CryptoShadowEntry *entry = opaque;
    CXLCryptoGuardState *state;

    if (!entry) {
        return;
    }

    state = entry->parent_state;
    if (!state) {
        return;
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  CRYPTO_GUARD_LOG_PREFIX "Timeout on addr 0x%lx held by device %u\n",
                  entry->addr, entry->device_id);

    state->timeouts++;

    /* Revoke exclusive access */
    cxl_crypto_guard_revoke_exclusive(state, entry->addr);

    /* Recover authoritative state from shadow */
    cxl_crypto_guard_recover_state(state, entry->addr);

    /* Quarantine the device */
    quarantine_device(state, entry->device_id);
}

/**
 * Install shadow and grant exclusive access
 *
 * Flowchart: "Install shadow & grant" step
 * Actions:
 * - Create shadow entry in DEVICE-PRIVATE DRAM (not host memory!)
 * - Encode {epoch, owner, hash}
 * - Arm watchdog
 * - Host-biased scheduling
 *
 * NOTE: In a real Type 1 device, this would:
 * 1. Allocate shadow space in device's local DRAM/SRAM
 * 2. DMA the cacheline data from host memory to device-private shadow
 * 3. Store metadata (epoch, owner, hash) in device registers
 * 4. Program hardware watchdog timer in device
 *
 * For QEMU emulation, we emulate device-private DRAM by allocating
 * shadow_data in the CryptoShadowEntry structure, but conceptually
 * this lives on the CXL device, NOT in host memory.
 */
int cxl_crypto_guard_install_shadow(CXLCryptoGuardState *state,
                                     hwaddr addr,
                                     uint32_t device_id,
                                     const uint8_t *data)
{
    CryptoShadowEntry *entry;

    if (!state || !data) {
        return -1;
    }

    qemu_mutex_lock(&state->shadow_lock);

    /* Check if shadow already exists */
    entry = find_shadow_entry(state, addr);
    if (entry) {
        /* Update existing shadow IN DEVICE-PRIVATE DRAM */
        memcpy(entry->shadow_data, data, 64);  /* Emulates DMA to device DRAM */
        entry->shadow_hash = compute_shadow_hash(data, 64);
        entry->epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        entry->device_id = device_id;
        entry->exclusive_granted = true;
        entry->proof_validated = false;
        entry->quarantined = false;

        /* Reset watchdog (in device hardware timer) */
        if (entry->watchdog) {
            timer_del(entry->watchdog);
            timer_mod(entry->watchdog,
                     qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + entry->timeout_ns);
        }

        qemu_mutex_unlock(&state->shadow_lock);
        return 0;
    }

    /* Check shadow entry limit */
    int count = 0;
    QLIST_FOREACH(entry, &state->shadow_entries, next) {
        count++;
    }
    if (count >= MAX_SHADOW_ENTRIES) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      CRYPTO_GUARD_LOG_PREFIX "Shadow entry limit reached\n");
        qemu_mutex_unlock(&state->shadow_lock);
        return -1;
    }

    /* Create new shadow entry
     * NOTE: In real hardware, this would allocate a slot in device-private
     * DRAM/SRAM (e.g., on-chip shadow cache in FPGA/ASIC)
     */
    entry = g_new0(CryptoShadowEntry, 1);
    entry->addr = addr;
    entry->epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    entry->device_id = device_id;
    entry->region_type = 0; /* Will be detected/set later */
    entry->parent_state = state; /* Back-pointer for timeout handler */

    /* Copy shadow data to DEVICE-PRIVATE DRAM (emulated via DMA) */
    memcpy(entry->shadow_data, data, 64);  /* Emulates: Device DMA from host to local DRAM */
    entry->shadow_hash = compute_shadow_hash(data, 64);  /* Computed in device hardware */

    /* Initialize proof metadata */
    memset(entry->proof_data, 0, sizeof(entry->proof_data));
    entry->proof_timestamp = 0;

    /* Set up watchdog timer */
    entry->timeout_ns = state->default_timeout_ns;
    entry->watchdog = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                   cxl_crypto_guard_timeout_handler,
                                   entry);
    timer_mod(entry->watchdog,
             qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + entry->timeout_ns);

    /* Initialize state */
    entry->exclusive_granted = true;
    entry->proof_validated = false;
    entry->quarantined = false;

    /* Add to list */
    QLIST_INSERT_HEAD(&state->shadow_entries, entry, next);

    state->shadows_created++;
    state->total_accesses++;

    qemu_mutex_unlock(&state->shadow_lock);

    qemu_log_mask(LOG_UNIMP,
                  CRYPTO_GUARD_LOG_PREFIX "Shadow installed at 0x%lx for device %u (epoch=%lu)\n",
                  addr, device_id, entry->epoch);

    return 0;
}

/**
 * Device update with proof
 *
 * Flowchart: "Device update + local proof" step
 * Actions:
 * - Device mutates shadowed line
 * - Generate proof via eBPF coprocessor
 * - Host collects metadata for later validation
 */
int cxl_crypto_guard_device_update(CXLCryptoGuardState *state,
                                    hwaddr addr,
                                    uint32_t device_id,
                                    const uint8_t *new_data,
                                    const uint8_t *proof,
                                    size_t proof_len)
{
    CryptoShadowEntry *entry;

    if (!state || !new_data) {
        return -1;
    }

    qemu_mutex_lock(&state->shadow_lock);

    entry = find_shadow_entry(state, addr);
    if (!entry) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      CRYPTO_GUARD_LOG_PREFIX "No shadow entry for addr 0x%lx\n",
                      addr);
        qemu_mutex_unlock(&state->shadow_lock);
        return -1;
    }

    /* Verify device ownership */
    if (entry->device_id != device_id) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      CRYPTO_GUARD_LOG_PREFIX "Device %u does not own addr 0x%lx (owner=%u)\n",
                      device_id, addr, entry->device_id);
        qemu_mutex_unlock(&state->shadow_lock);
        return -1;
    }

    /* Store proof data */
    if (proof && proof_len > 0) {
        size_t copy_len = proof_len < sizeof(entry->proof_data) ?
                         proof_len : sizeof(entry->proof_data);
        memcpy(entry->proof_data, proof, copy_len);
        entry->proof_timestamp = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    }

    /* Update shadow with new data for comparison */
    /* Note: Actual data is NOT committed yet, only stored for validation */

    qemu_mutex_unlock(&state->shadow_lock);

    qemu_log_mask(LOG_UNIMP,
                  CRYPTO_GUARD_LOG_PREFIX "Device %u updated addr 0x%lx with proof (len=%zu)\n",
                  device_id, addr, proof_len);

    return 0;
}

/**
 * Validate proof and decide commit/quarantine
 *
 * Flowchart: "Proof validates?" decision
 * YES → "Commit" (apply to kernel state; release ownership; append journal)
 * NO → "Quarantine & rollback" (quarantine region/PASID; rollback from shadow)
 */
ProofValidationResult cxl_crypto_guard_validate_proof(CXLCryptoGuardState *state,
                                                        hwaddr addr)
{
    CryptoShadowEntry *entry;
    ProofValidationResult result;

    if (!state) {
        return PROOF_INVALID;
    }

    qemu_mutex_lock(&state->shadow_lock);

    entry = find_shadow_entry(state, addr);
    if (!entry) {
        qemu_mutex_unlock(&state->shadow_lock);
        return PROOF_INVALID;
    }

    /* Check for timeout */
    uint64_t current_time = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (current_time - entry->epoch > entry->timeout_ns) {
        qemu_mutex_unlock(&state->shadow_lock);
        return PROOF_TIMEOUT;
    }

    /* Validate proof (simplified - real implementation would use crypto verification) */
    bool proof_valid = true;

    /* Check if proof exists */
    if (entry->proof_timestamp == 0) {
        proof_valid = false;
    }

    /* Check proof freshness */
    if (entry->proof_timestamp < entry->epoch) {
        proof_valid = false;
    }

    /* Simplified validation: check proof is not all zeros */
    bool all_zeros = true;
    for (size_t i = 0; i < sizeof(entry->proof_data); i++) {
        if (entry->proof_data[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    if (all_zeros && entry->proof_timestamp > 0) {
        proof_valid = false;
    }

    if (proof_valid) {
        entry->proof_validated = true;
        result = PROOF_VALID;
        qemu_log_mask(LOG_UNIMP,
                      CRYPTO_GUARD_LOG_PREFIX "Proof validated for addr 0x%lx\n",
                      addr);
    } else {
        state->proof_failures++;
        result = PROOF_INVALID;
        qemu_log_mask(LOG_GUEST_ERROR,
                      CRYPTO_GUARD_LOG_PREFIX "Proof validation FAILED for addr 0x%lx\n",
                      addr);
    }

    qemu_mutex_unlock(&state->shadow_lock);

    return result;
}

/**
 * Commit validated update to kernel state
 *
 * Flowchart: "Commit" step (after proof validates)
 * Actions:
 * - Apply to kernel state
 * - Release ownership
 * - Append journal
 */
void cxl_crypto_guard_commit_update(CXLCryptoGuardState *state, hwaddr addr)
{
    CryptoShadowEntry *entry;

    if (!state) {
        return;
    }

    qemu_mutex_lock(&state->shadow_lock);

    entry = find_shadow_entry(state, addr);
    if (!entry) {
        qemu_mutex_unlock(&state->shadow_lock);
        return;
    }

    if (!entry->proof_validated) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      CRYPTO_GUARD_LOG_PREFIX "Cannot commit - proof not validated for addr 0x%lx\n",
                      addr);
        qemu_mutex_unlock(&state->shadow_lock);
        return;
    }

    /* Release exclusive access */
    entry->exclusive_granted = false;

    /* Cancel watchdog */
    if (entry->watchdog) {
        timer_del(entry->watchdog);
    }

    state->shadows_committed++;

    qemu_log_mask(LOG_UNIMP,
                  CRYPTO_GUARD_LOG_PREFIX "Committed update for addr 0x%lx (device %u)\n",
                  addr, entry->device_id);

    /* Remove shadow entry (or keep for audit trail) */
    /* For now, keep it for potential reuse */

    qemu_mutex_unlock(&state->shadow_lock);
}

/**
 * Quarantine device and rollback from shadow
 *
 * Flowchart: "Quarantine & rollback" step (after proof fails)
 * Actions:
 * - Quarantine region/PASID
 * - Rollback from shadow
 * - Alert & rate-limit
 */
void cxl_crypto_guard_quarantine(CXLCryptoGuardState *state,
                                  hwaddr addr,
                                  uint32_t device_id)
{
    CryptoShadowEntry *entry;

    if (!state) {
        return;
    }

    qemu_mutex_lock(&state->shadow_lock);

    /* Quarantine the device */
    quarantine_device(state, device_id);

    /* Find and mark shadow entry as quarantined */
    entry = find_shadow_entry(state, addr);
    if (entry) {
        entry->quarantined = true;
        entry->exclusive_granted = false;

        /* Cancel watchdog */
        if (entry->watchdog) {
            timer_del(entry->watchdog);
        }

        /* Rollback from shadow - restore original data */
        /* In real implementation, would write shadow_data back to memory */
        qemu_log_mask(LOG_GUEST_ERROR,
                      CRYPTO_GUARD_LOG_PREFIX "Rolled back addr 0x%lx to shadow (hash=0x%lx)\n",
                      addr, entry->shadow_hash);
    }

    qemu_mutex_unlock(&state->shadow_lock);

    qemu_log_mask(LOG_GUEST_ERROR,
                  CRYPTO_GUARD_LOG_PREFIX "QUARANTINED device %u, addr 0x%lx rolled back\n",
                  device_id, addr);
}

/**
 * Revoke exclusive access (timeout/fault path)
 *
 * Flowchart: "Revoke / degrade" step
 * Actions:
 * - Force writeback
 * - Fence PASID/region
 * - Blacklist or throttle offender
 */
void cxl_crypto_guard_revoke_exclusive(CXLCryptoGuardState *state, hwaddr addr)
{
    CryptoShadowEntry *entry;

    if (!state) {
        return;
    }

    qemu_mutex_lock(&state->shadow_lock);

    entry = find_shadow_entry(state, addr);
    if (!entry) {
        qemu_mutex_unlock(&state->shadow_lock);
        return;
    }

    /* Force writeback (if device still responsive) */
    /* In real implementation, would issue cache writeback command */

    /* Revoke exclusive access */
    entry->exclusive_granted = false;

    /* Cancel watchdog */
    if (entry->watchdog) {
        timer_del(entry->watchdog);
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  CRYPTO_GUARD_LOG_PREFIX "Revoked exclusive access for addr 0x%lx (device %u)\n",
                  addr, entry->device_id);

    qemu_mutex_unlock(&state->shadow_lock);
}

/**
 * Recover authoritative state from shadow
 *
 * Flowchart: "Recover authoritative state" step
 * Actions:
 * - Reconstruct from shadow + host log
 * - Mark device as suspect
 */
int cxl_crypto_guard_recover_state(CXLCryptoGuardState *state, hwaddr addr)
{
    CryptoShadowEntry *entry;

    if (!state) {
        return -1;
    }

    qemu_mutex_lock(&state->shadow_lock);

    entry = find_shadow_entry(state, addr);
    if (!entry) {
        qemu_mutex_unlock(&state->shadow_lock);
        return -1;
    }

    /* Restore from shadow copy */
    /* In real implementation, would write shadow_data back to memory */

    /* Verify shadow integrity */
    uint64_t expected_hash = entry->shadow_hash;
    uint64_t actual_hash = compute_shadow_hash(entry->shadow_data, 64);

    if (expected_hash != actual_hash) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      CRYPTO_GUARD_LOG_PREFIX "Shadow corruption detected at 0x%lx!\n",
                      addr);
        qemu_mutex_unlock(&state->shadow_lock);
        return -1;
    }

    state->recoveries++;

    qemu_log_mask(LOG_UNIMP,
                  CRYPTO_GUARD_LOG_PREFIX "Recovered state for addr 0x%lx from shadow (epoch=%lu)\n",
                  addr, entry->epoch);

    qemu_mutex_unlock(&state->shadow_lock);

    return 0;
}

/**
 * Initialize crypto guard
 */
CXLCryptoGuardState *cxl_crypto_guard_init(CXLCacheCoherencyState *cache_state,
                                            uint32_t default_protection)
{
    CXLCryptoGuardState *state;

    if (!cache_state) {
        return NULL;
    }

    state = g_new0(CXLCryptoGuardState, 1);
    state->cache_state = cache_state;
    state->default_protection_level = default_protection;
    state->auto_detect_crypto_regions = true;
    state->default_timeout_ns = DEFAULT_TIMEOUT_NS;

    QLIST_INIT(&state->shadow_entries);
    qemu_mutex_init(&state->shadow_lock);

    /* Initialize statistics */
    state->total_accesses = 0;
    state->shadows_created = 0;
    state->shadows_committed = 0;
    state->policy_denials = 0;
    state->timeouts = 0;
    state->proof_failures = 0;
    state->recoveries = 0;

    /* Initialize quarantine bitmap */
    memset(state->quarantined_devices, 0, sizeof(state->quarantined_devices));

    state->device_online = true;

    qemu_log_mask(LOG_UNIMP,
                  CRYPTO_GUARD_LOG_PREFIX "Initialized (protection_level=%u, timeout=%lu ns)\n",
                  default_protection, state->default_timeout_ns);

    return state;
}

/**
 * Cleanup crypto guard
 */
void cxl_crypto_guard_cleanup(CXLCryptoGuardState *state)
{
    CryptoShadowEntry *entry, *next;

    if (!state) {
        return;
    }

    qemu_mutex_lock(&state->shadow_lock);

    /* Free all shadow entries */
    QLIST_FOREACH_SAFE(entry, &state->shadow_entries, next, next) {
        if (entry->watchdog) {
            timer_free(entry->watchdog);
        }
        QLIST_REMOVE(entry, next);
        g_free(entry);
    }

    qemu_mutex_unlock(&state->shadow_lock);
    qemu_mutex_destroy(&state->shadow_lock);

    qemu_log_mask(LOG_UNIMP,
                  CRYPTO_GUARD_LOG_PREFIX "Cleanup complete (stats: %lu accesses, %lu shadows, %lu commits, %lu recoveries)\n",
                  state->total_accesses, state->shadows_created,
                  state->shadows_committed, state->recoveries);

    g_free(state);
}

/**
 * Handle device offline (fault/hot-unplug)
 */
void cxl_crypto_guard_device_offline(CXLCryptoGuardState *state)
{
    CryptoShadowEntry *entry;

    if (!state) {
        return;
    }

    qemu_log_mask(LOG_UNIMP,
                  CRYPTO_GUARD_LOG_PREFIX "Device going offline - recovering all shadows\n");

    qemu_mutex_lock(&state->shadow_lock);

    state->device_online = false;

    /* Revoke all exclusive accesses and recover */
    QLIST_FOREACH(entry, &state->shadow_entries, next) {
        if (entry->exclusive_granted) {
            entry->exclusive_granted = false;

            if (entry->watchdog) {
                timer_del(entry->watchdog);
            }

            /* Recover from shadow */
            cxl_crypto_guard_recover_state(state, entry->addr);
        }
    }

    qemu_mutex_unlock(&state->shadow_lock);

    /* Also call underlying cache coherency handler */
    if (state->cache_state) {
        cxl_cache_device_offline(state->cache_state);
    }
}

/**
 * Handle device online
 */
void cxl_crypto_guard_device_online(CXLCryptoGuardState *state)
{
    if (!state) {
        return;
    }

    qemu_log_mask(LOG_UNIMP,
                  CRYPTO_GUARD_LOG_PREFIX "Device coming online\n");

    state->device_online = true;

    /* Call underlying cache coherency handler */
    if (state->cache_state) {
        cxl_cache_device_online(state->cache_state);
    }
}

/**
 * Get statistics
 */
void cxl_crypto_guard_get_stats(CXLCryptoGuardState *state, void *stats_out)
{
    struct {
        uint64_t total_accesses;
        uint64_t shadows_created;
        uint64_t shadows_committed;
        uint64_t policy_denials;
        uint64_t timeouts;
        uint64_t proof_failures;
        uint64_t recoveries;
    } *stats = stats_out;

    if (!state || !stats) {
        return;
    }

    stats->total_accesses = state->total_accesses;
    stats->shadows_created = state->shadows_created;
    stats->shadows_committed = state->shadows_committed;
    stats->policy_denials = state->policy_denials;
    stats->timeouts = state->timeouts;
    stats->proof_failures = state->proof_failures;
    stats->recoveries = state->recoveries;
}
