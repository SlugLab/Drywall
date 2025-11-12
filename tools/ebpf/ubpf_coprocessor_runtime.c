/*
 * Userspace eBPF Coprocessor Runtime for CXL Type 1 Device
 *
 * This simulates the eBPF coprocessor running inside the CXL device.
 * It provides a host-callable interface to execute firewall checks,
 * proof generation, and proof validation.
 *
 * Compile:
 *   gcc -o ubpf_coprocessor_runtime ubpf_coprocessor_runtime.c -lpthread
 *
 * Usage:
 *   ./ubpf_coprocessor_runtime
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

/* eBPF Map Emulation */
#define MAX_FIREWALL_RULES 256
#define MAX_DEVICES 256
#define MAX_SHADOWS 4096

/* Firewall actions */
enum firewall_action {
    FW_ALLOW = 0,
    FW_DENY = 1,
    FW_RATE_LIMIT = 2,
    FW_QUARANTINE = 3,
};

/* Firewall rule */
struct firewall_rule {
    uint64_t addr_start;
    uint64_t addr_end;
    uint32_t region_type;
    uint32_t allowed_devices[8];  /* Bitmap for 256 devices */
    uint32_t max_access_rate;
    uint8_t deny_write;
    uint8_t deny_read;
    uint8_t enabled;
    uint8_t padding;
} __attribute__((packed));

/* Shadow metadata */
struct shadow_metadata {
    uint64_t addr;
    uint64_t epoch;
    uint64_t sequence;
    uint32_t device_id;
    uint32_t region_type;
    uint8_t shadow_data[64];
    uint64_t shadow_hash;
} __attribute__((packed));

/* Crypto proof */
struct crypto_proof {
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

/* Device key */
struct device_key {
    uint32_t device_id;
    uint8_t key[32];
} __attribute__((packed));

/* Statistics */
struct stats_entry {
    uint64_t total_accesses;
    uint64_t firewall_allows;
    uint64_t firewall_denies;
    uint64_t firewall_rate_limits;
    uint64_t firewall_quarantine_blocks;
    uint64_t proofs_generated;
    uint64_t proofs_validated;
    uint64_t proofs_failed;
    uint64_t exec_verifications;
    uint64_t exec_iv_violations;
    uint64_t exec_path_violations;
} __attribute__((packed));

/* BPF Maps (simulated in userspace) */
static struct firewall_rule firewall_rules[MAX_FIREWALL_RULES];
static uint64_t device_access_count[MAX_DEVICES];
static uint32_t quarantine_bitmap[8];  /* 256 bits */
static struct shadow_metadata shadows[MAX_SHADOWS];
static struct device_key device_keys[MAX_DEVICES];
static struct stats_entry stats;
static pthread_mutex_t maps_lock = PTHREAD_MUTEX_INITIALIZER;

/* Helper functions */
static uint64_t get_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint64_t compute_hash(const uint8_t *data, uint32_t len) {
    uint64_t hash = 0xcbf29ce484222325ULL;  /* FNV-1a */
    for (uint32_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static void compute_hmac(const uint8_t *data, uint32_t len,
                         const uint8_t *key, uint8_t *out) {
    uint64_t h1 = compute_hash(data, len);
    uint64_t h2 = compute_hash(key, 32);
    uint64_t hmac = h1 ^ h2;

    for (int i = 0; i < 32; i++) {
        out[i] = (uint8_t)((hmac >> (i % 8)) & 0xFF);
    }
}

static int is_device_quarantined(uint32_t device_id) {
    if (device_id >= 256) return 0;

    uint32_t bitmap_idx = device_id / 32;
    uint32_t bit_pos = device_id % 32;

    return (quarantine_bitmap[bitmap_idx] & (1U << bit_pos)) != 0;
}

static void set_device_quarantined(uint32_t device_id) {
    if (device_id >= 256) return;

    uint32_t bitmap_idx = device_id / 32;
    uint32_t bit_pos = device_id % 32;

    pthread_mutex_lock(&maps_lock);
    quarantine_bitmap[bitmap_idx] |= (1U << bit_pos);
    pthread_mutex_unlock(&maps_lock);
}

static int is_device_allowed(struct firewall_rule *rule, uint32_t device_id) {
    if (device_id >= 256) return 0;

    uint32_t bitmap_idx = device_id / 32;
    uint32_t bit_pos = device_id % 32;

    return (rule->allowed_devices[bitmap_idx] & (1U << bit_pos)) != 0;
}

static struct shadow_metadata *find_shadow(uint64_t addr) {
    for (int i = 0; i < MAX_SHADOWS; i++) {
        if (shadows[i].addr == addr && shadows[i].sequence > 0) {
            return &shadows[i];
        }
    }
    return NULL;
}

static struct device_key *find_device_key(uint32_t device_id) {
    if (device_id >= MAX_DEVICES) return NULL;

    if (device_keys[device_id].device_id == device_id) {
        return &device_keys[device_id];
    }
    return NULL;
}

/* eBPF Programs (simulated) */

int cxl_firewall_check(uint64_t addr, uint32_t device_id, uint8_t is_write) {
    pthread_mutex_lock(&maps_lock);

    stats.total_accesses++;

    /* Check 1: Device quarantined? */
    if (is_device_quarantined(device_id)) {
        stats.firewall_quarantine_blocks++;
        pthread_mutex_unlock(&maps_lock);
        return FW_QUARANTINE;
    }

    /* Check 2: Rate limiting */
    if (device_access_count[device_id] > 1000) {
        stats.firewall_rate_limits++;
        pthread_mutex_unlock(&maps_lock);
        return FW_RATE_LIMIT;
    }
    device_access_count[device_id]++;

    /* Check 3: Firewall rules */
    for (uint32_t rule_id = 0; rule_id < 32; rule_id++) {
        struct firewall_rule *rule = &firewall_rules[rule_id];
        if (!rule->enabled) continue;

        if (addr >= rule->addr_start && addr <= rule->addr_end) {
            /* Check device allowed */
            if (!is_device_allowed(rule, device_id)) {
                stats.firewall_denies++;
                pthread_mutex_unlock(&maps_lock);
                return FW_DENY;
            }

            /* Check read/write permissions */
            if (is_write && rule->deny_write) {
                stats.firewall_denies++;
                pthread_mutex_unlock(&maps_lock);
                return FW_DENY;
            }
            if (!is_write && rule->deny_read) {
                stats.firewall_denies++;
                pthread_mutex_unlock(&maps_lock);
                return FW_DENY;
            }
        }
    }

    /* Default: ALLOW */
    stats.firewall_allows++;
    pthread_mutex_unlock(&maps_lock);
    return FW_ALLOW;
}

int cxl_register_shadow(uint64_t addr, uint32_t device_id,
                        uint32_t region_type, const uint8_t *data) {
    pthread_mutex_lock(&maps_lock);

    /* Find free shadow slot */
    int slot = -1;
    for (int i = 0; i < MAX_SHADOWS; i++) {
        if (shadows[i].sequence == 0) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&maps_lock);
        return -1;  /* No space */
    }

    shadows[slot].addr = addr;
    shadows[slot].epoch = get_timestamp();
    shadows[slot].sequence = 1;
    shadows[slot].device_id = device_id;
    shadows[slot].region_type = region_type;
    memcpy(shadows[slot].shadow_data, data, 64);
    shadows[slot].shadow_hash = compute_hash(data, 64);

    pthread_mutex_unlock(&maps_lock);

    printf("[COPROCESSOR] Shadow registered: addr=0x%lx device=%u hash=0x%lx\n",
           addr, device_id, shadows[slot].shadow_hash);

    return 0;
}

int cxl_generate_proof(uint64_t addr, uint32_t device_id,
                       const uint8_t *old_data, const uint8_t *new_data,
                       struct crypto_proof *proof_out) {
    pthread_mutex_lock(&maps_lock);

    /* Find shadow */
    struct shadow_metadata *shadow = find_shadow(addr);
    if (!shadow) {
        pthread_mutex_unlock(&maps_lock);
        return -1;
    }

    /* Find device key */
    struct device_key *key = find_device_key(device_id);
    if (!key) {
        pthread_mutex_unlock(&maps_lock);
        return -1;
    }

    /* Generate proof */
    proof_out->timestamp = get_timestamp();
    proof_out->sequence = shadow->sequence + 1;
    proof_out->shadow_hash = compute_hash(old_data, 64);
    proof_out->new_hash = compute_hash(new_data, 64);
    proof_out->addr = addr;
    proof_out->device_id = device_id;
    proof_out->operation_type = 0;
    proof_out->exec_trace_checksum = 0;
    proof_out->exec_step_count = 0;
    proof_out->exec_flags = 0;

    /* Compute HMAC */
    compute_hmac((uint8_t *)proof_out, sizeof(*proof_out) - 40,
                 key->key, proof_out->hmac);

    stats.proofs_generated++;
    pthread_mutex_unlock(&maps_lock);

    printf("[COPROCESSOR] Proof generated: addr=0x%lx seq=%lu hash=0x%lx->0x%lx\n",
           addr, proof_out->sequence, proof_out->shadow_hash, proof_out->new_hash);

    return 0;
}

int cxl_validate_proof(const struct crypto_proof *proof) {
    pthread_mutex_lock(&maps_lock);

    /* Find shadow */
    struct shadow_metadata *shadow = find_shadow(proof->addr);
    if (!shadow) {
        stats.proofs_failed++;
        pthread_mutex_unlock(&maps_lock);
        return 1;  /* INVALID_HASH */
    }

    /* Validate sequence */
    if (proof->sequence != shadow->sequence + 1) {
        stats.proofs_failed++;
        pthread_mutex_unlock(&maps_lock);
        return 2;  /* INVALID_SEQUENCE */
    }

    /* Validate shadow hash */
    if (proof->shadow_hash != shadow->shadow_hash) {
        stats.proofs_failed++;
        pthread_mutex_unlock(&maps_lock);
        return 3;  /* INVALID_HASH */
    }

    /* Find device key */
    struct device_key *key = find_device_key(proof->device_id);
    if (!key) {
        stats.proofs_failed++;
        pthread_mutex_unlock(&maps_lock);
        return 1;  /* INVALID_HMAC */
    }

    /* Verify HMAC */
    uint8_t computed_hmac[32];
    compute_hmac((const uint8_t *)proof, sizeof(*proof) - 40,
                 key->key, computed_hmac);

    if (memcmp(computed_hmac, proof->hmac, 32) != 0) {
        stats.proofs_failed++;
        pthread_mutex_unlock(&maps_lock);
        return 1;  /* INVALID_HMAC */
    }

    /* Update shadow */
    shadow->sequence = proof->sequence;
    shadow->shadow_hash = proof->new_hash;

    stats.proofs_validated++;
    pthread_mutex_unlock(&maps_lock);

    printf("[COPROCESSOR] Proof validated: addr=0x%lx seq=%lu ✓\n",
           proof->addr, proof->sequence);

    return 0;  /* VALID */
}

void cxl_set_device_key(uint32_t device_id, const uint8_t *key) {
    pthread_mutex_lock(&maps_lock);

    if (device_id < MAX_DEVICES) {
        device_keys[device_id].device_id = device_id;
        memcpy(device_keys[device_id].key, key, 32);
        printf("[COPROCESSOR] Device key set: device=%u\n", device_id);
    }

    pthread_mutex_unlock(&maps_lock);
}

void cxl_add_firewall_rule(uint32_t rule_id, uint64_t addr_start,
                           uint64_t addr_end, uint32_t device_id_allow) {
    pthread_mutex_lock(&maps_lock);

    if (rule_id < MAX_FIREWALL_RULES) {
        firewall_rules[rule_id].addr_start = addr_start;
        firewall_rules[rule_id].addr_end = addr_end;
        firewall_rules[rule_id].region_type = 1;

        /* Set allowed device in bitmap */
        uint32_t bitmap_idx = device_id_allow / 32;
        uint32_t bit_pos = device_id_allow % 32;
        firewall_rules[rule_id].allowed_devices[bitmap_idx] |= (1U << bit_pos);

        firewall_rules[rule_id].enabled = 1;

        printf("[COPROCESSOR] Firewall rule added: rule=%u addr=0x%lx-0x%lx device=%u\n",
               rule_id, addr_start, addr_end, device_id_allow);
    }

    pthread_mutex_unlock(&maps_lock);
}

void cxl_print_stats(void) {
    pthread_mutex_lock(&maps_lock);

    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("  eBPF Coprocessor Statistics\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("Total accesses:          %lu\n", stats.total_accesses);
    printf("Firewall allows:         %lu\n", stats.firewall_allows);
    printf("Firewall denies:         %lu\n", stats.firewall_denies);
    printf("Firewall rate limits:    %lu\n", stats.firewall_rate_limits);
    printf("Firewall quarantines:    %lu\n", stats.firewall_quarantine_blocks);
    printf("Proofs generated:        %lu\n", stats.proofs_generated);
    printf("Proofs validated:        %lu\n", stats.proofs_validated);
    printf("Proofs failed:           %lu\n", stats.proofs_failed);
    printf("Exec verifications:      %lu\n", stats.exec_verifications);
    printf("IV violations:           %lu\n", stats.exec_iv_violations);
    printf("Path violations:         %lu\n", stats.exec_path_violations);
    printf("═══════════════════════════════════════════════════════════\n\n");

    pthread_mutex_unlock(&maps_lock);
}

/* Demo main function */
int main(void) {
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  CXL eBPF Coprocessor Runtime (Userspace Simulation)\n");
    printf("═══════════════════════════════════════════════════════════\n\n");

    /* Initialize device key for device 42 */
    uint8_t test_key[32] = {0xDE, 0xAD, 0xBE, 0xEF};
    for (int i = 4; i < 32; i++) test_key[i] = i;
    cxl_set_device_key(42, test_key);

    /* Add firewall rule: protect LUKS header region */
    uint64_t luks_header_start = 0x1000;
    uint64_t luks_header_end = 0x1FFF;
    cxl_add_firewall_rule(0, luks_header_start, luks_header_end, 42);

    printf("\n--- DEMO: CXL Cacheline Protection Flow ---\n\n");

    /* Step 1: Device requests exclusive access */
    uint64_t test_addr = 0x1800;  /* In LUKS header region */
    uint32_t test_device = 42;

    printf("Step 1: Device %u requests exclusive access to 0x%lx\n", test_device, test_addr);
    int fw_result = cxl_firewall_check(test_addr, test_device, 1);

    if (fw_result == FW_ALLOW) {
        printf("  → Firewall: ALLOW ✓\n\n");
    } else {
        printf("  → Firewall: DENY ✗ (reason=%d)\n\n", fw_result);
        return 1;
    }

    /* Step 2: Install shadow before granting exclusive */
    printf("Step 2: Installing shadow in device-private DRAM\n");
    uint8_t original_data[64];
    memset(original_data, 0xAA, 64);
    /* Simulate LUKS header IV counter */
    uint64_t iv_counter = 12345;
    memcpy(original_data, &iv_counter, sizeof(iv_counter));

    if (cxl_register_shadow(test_addr, test_device, 1, original_data) == 0) {
        printf("  → Shadow installed ✓\n\n");
    } else {
        printf("  → Shadow installation failed ✗\n\n");
        return 1;
    }

    /* Step 3: Device updates cacheline (increments IV) */
    printf("Step 3: Device updates cacheline (IV increment)\n");
    uint8_t new_data[64];
    memcpy(new_data, original_data, 64);
    uint64_t new_iv = iv_counter + 1;
    memcpy(new_data, &new_iv, sizeof(new_iv));
    printf("  → IV: %lu → %lu\n", iv_counter, new_iv);

    /* Step 4: Device generates proof */
    printf("\nStep 4: Device generates cryptographic proof\n");
    struct crypto_proof proof;
    if (cxl_generate_proof(test_addr, test_device, original_data, new_data, &proof) == 0) {
        printf("  → Proof generated ✓\n");
        printf("  → HMAC: ");
        for (int i = 0; i < 8; i++) printf("%02x", proof.hmac[i]);
        printf("...\n\n");
    } else {
        printf("  → Proof generation failed ✗\n\n");
        return 1;
    }

    /* Step 5: Host validates proof */
    printf("Step 5: Host validates proof before commit\n");
    int validation_result = cxl_validate_proof(&proof);
    if (validation_result == 0) {
        printf("  → Proof validation: VALID ✓\n");
        printf("  → Commit allowed\n\n");
    } else {
        printf("  → Proof validation: INVALID ✗ (code=%d)\n", validation_result);
        printf("  → Commit denied, device quarantined\n\n");
        set_device_quarantined(test_device);
    }

    /* Step 6: Test quarantine */
    printf("Step 6: Testing quarantine (simulating malicious device)\n");
    uint32_t bad_device = 99;
    set_device_quarantined(bad_device);

    int quarantine_test = cxl_firewall_check(test_addr, bad_device, 1);
    if (quarantine_test == FW_QUARANTINE) {
        printf("  → Device %u is quarantined ✓\n", bad_device);
        printf("  → All future accesses blocked\n\n");
    }

    /* Print final statistics */
    cxl_print_stats();

    printf("✓ Demo completed successfully!\n\n");
    printf("This demonstrates:\n");
    printf("  • Firewall protection of LUKS header\n");
    printf("  • Shadow-before-exclusivity enforcement\n");
    printf("  • Cryptographic proof generation\n");
    printf("  • Host-side proof validation\n");
    printf("  • Device quarantine on policy violation\n\n");

    return 0;
}
