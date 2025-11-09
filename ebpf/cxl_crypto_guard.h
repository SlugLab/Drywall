/*
 * CXL Crypto Guard Header
 *
 * Copyright (c) 2025 Drywall Project
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#ifndef CXL_CRYPTO_GUARD_H
#define CXL_CRYPTO_GUARD_H

#include <stdint.h>
#include <stddef.h>

/* Forward declarations */
typedef struct CXLCryptoGuardState CXLCryptoGuardState;

/* Crypto metadata region types */
#define CRYPTO_REGION_LUKS_HEADER     0x01
#define CRYPTO_REGION_IV_COUNTER      0x02
#define CRYPTO_REGION_INTEGRITY_TAG   0x04
#define CRYPTO_REGION_CRYPTO_CTX      0x08
#define CRYPTO_REGION_KEY_MATERIAL    0x10
#define CRYPTO_REGION_DMCRYPT_STATE   0x20

/* Protection levels */
#define PROTECTION_NONE               0
#define PROTECTION_DENY_EXCLUSIVE     1
#define PROTECTION_SHADOW_REQUIRED    2
#define PROTECTION_READ_ONLY          3
#define PROTECTION_COMPLETE_DENY      4

/* Crypto operation types */
enum CryptoOperation {
    CRYPTO_OP_KEY_LOAD = 0,
    CRYPTO_OP_IV_UPDATE = 1,
    CRYPTO_OP_ENCRYPT = 2,
    CRYPTO_OP_DECRYPT = 3,
    CRYPTO_OP_KEY_DERIVATION = 4,
    CRYPTO_OP_INTEGRITY_CHECK = 5,
    CRYPTO_OP_HEADER_UPDATE = 6,
};

/* Structures matching eBPF definitions */
struct crypto_region {
    uint64_t start_addr;
    uint64_t end_addr;
    uint32_t region_type;
    uint32_t protection_level;
    uint64_t last_shadow_time;
    uint32_t access_count;
    uint32_t violation_count;
    uint8_t device_allowlist[32];
} __attribute__((packed));

struct crypto_context_shadow {
    uint64_t addr;
    uint64_t timestamp;
    uint64_t version;
    uint32_t device_id;
    uint32_t region_type;
    uint64_t key_slot_bitmap;
    uint64_t iv_counter;
    uint32_t cipher_mode;
    uint32_t key_size;
    uint8_t data[256];
    uint8_t key_material[64];
    uint8_t integrity_tag[32];
    uint64_t checksum;
} __attribute__((packed));

struct crypto_access_event {
    uint64_t timestamp;
    uint64_t addr;
    uint32_t device_id;
    uint32_t operation_type;
    uint32_t region_type;
    uint32_t protection_level;
    uint8_t access_granted;
    uint8_t shadow_created;
    uint8_t violation;
    uint8_t recovery_triggered;
} __attribute__((packed));

struct crypto_device_fault {
    uint64_t timestamp;
    uint32_t device_id;
    uint32_t fault_type;
    uint32_t affected_regions;
    uint32_t shadows_restored;
    uint64_t recovery_duration_ns;
} __attribute__((packed));

struct crypto_guard_stats {
    uint64_t total_accesses;
    uint64_t exclusive_denied;
    uint64_t shadows_created;
    uint64_t shadows_restored;
    uint64_t policy_violations;
    uint64_t device_faults;
    uint64_t integrity_failures;
    uint64_t recovery_operations;
    uint64_t operations[7];
    uint64_t region_accesses[6];
} __attribute__((packed));

/* Statistics structure for userspace */
typedef struct CryptoGuardStats {
    uint64_t total_accesses;
    uint64_t exclusive_denied;
    uint64_t shadows_created;
    uint64_t shadows_restored;
    uint64_t policy_violations;
    uint64_t device_faults;
    uint64_t integrity_failures;
    uint64_t recovery_operations;
    uint64_t operations[7];
    uint64_t region_accesses[6];
} CryptoGuardStats;

/* Event callback types */
typedef void (*CryptoEventCallback)(struct crypto_access_event *event, void *ctx);
typedef void (*CryptoFaultCallback)(struct crypto_device_fault *fault, void *ctx);

/* Initialization and cleanup */
CXLCryptoGuardState *cxl_crypto_guard_init(void);
void cxl_crypto_guard_cleanup(CXLCryptoGuardState *state);

/* Region protection management */
int cxl_crypto_guard_add_region(CXLCryptoGuardState *state, uint64_t start_addr,
                                uint64_t end_addr, uint32_t region_type,
                                uint32_t protection_level, uint8_t *device_allowlist);

/* High-level protection configuration */
int cxl_crypto_guard_protect_luks(CXLCryptoGuardState *state, uint64_t luks_header_addr,
                                  uint32_t protection_level);

int cxl_crypto_guard_protect_dmcrypt_state(CXLCryptoGuardState *state,
                                           uint64_t state_addr, uint64_t state_size,
                                           uint32_t protection_level);

int cxl_crypto_guard_protect_iv_counters(CXLCryptoGuardState *state,
                                         uint64_t iv_base_addr, uint64_t iv_size,
                                         uint32_t protection_level);

/* Shadow management and recovery */
int cxl_crypto_guard_restore_shadow(CXLCryptoGuardState *state, uint64_t addr,
                                   uint8_t *data_out, size_t data_len);

int cxl_crypto_guard_device_offline(CXLCryptoGuardState *state, uint32_t device_id);

/* Statistics and monitoring */
int cxl_crypto_guard_get_stats(CXLCryptoGuardState *state,
                              CryptoGuardStats *stats_out);

int cxl_crypto_guard_poll_events(CXLCryptoGuardState *state, int timeout_ms);

/* Event callbacks */
void cxl_crypto_guard_set_event_callback(CXLCryptoGuardState *state,
                                        CryptoEventCallback callback, void *ctx);

void cxl_crypto_guard_set_fault_callback(CXLCryptoGuardState *state,
                                        CryptoFaultCallback callback, void *ctx);

/* Global instance accessor */
CXLCryptoGuardState *cxl_crypto_guard_get_global(void);

#endif /* CXL_CRYPTO_GUARD_H */
