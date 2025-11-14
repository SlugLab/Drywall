/*
 * CXL Device Fuzzer - Advanced fuzzing for CXL Type 1 device and eBPF coprocessor
 *
 * Targets:
 *  - CXL cache coherency protocol (MESI)
 *  - eBPF coprocessor programs (firewall, shadow, proof)
 *  - Device state machine
 *  - Memory ordering and race conditions
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#define CACHELINE_SIZE 64
#define MAX_DEVICES 16
#define MAX_CONCURRENT 8
#define SHADOW_MAP_SIZE 1024
#define PROOF_MAP_SIZE 1024

/* Cache states (MESI) */
enum cache_state {
    CACHE_INVALID = 0,
    CACHE_SHARED,
    CACHE_EXCLUSIVE,
    CACHE_MODIFIED
};

/* Device states */
enum device_state {
    DEVICE_OFFLINE = 0,
    DEVICE_ONLINE,
    DEVICE_QUARANTINED,
    DEVICE_CRASHED
};

/* Fuzzing strategies */
enum fuzz_strategy {
    FUZZ_RANDOM = 0,
    FUZZ_RACE_CONDITION,
    FUZZ_INVALID_STATE,
    FUZZ_MALFORMED_PROOF,
    FUZZ_CONCURRENT_ACCESS,
    FUZZ_BOUNDARY,
    FUZZ_MEMORY_CORRUPTION,
    FUZZ_INTEGER_OVERFLOW,
    FUZZ_STATE_MACHINE,
    FUZZ_PROTOCOL_VIOLATION,
    FUZZ_DOUBLE_FREE,
    FUZZ_USE_AFTER_FREE,
    FUZZ_NUM_STRATEGIES
};

/* Fuzz input structure */
struct fuzz_input {
    uint8_t strategy;
    uint8_t device_id;
    uint8_t initial_state;
    uint8_t target_state;
    uint8_t concurrent_devices;
    uint8_t reserved[3];
    uint64_t target_addr;
    uint8_t payload[CACHELINE_SIZE];
} __attribute__((packed));

/* Cacheline structure */
struct cacheline {
    uint8_t data[CACHELINE_SIZE];
    enum cache_state state;
    uint32_t device_id;
    uint32_t sequence;
    pthread_mutex_t lock;
} __attribute__((aligned(64)));

/* Shadow structure */
struct shadow {
    uint8_t data[CACHELINE_SIZE];
    uint32_t hash;
    uint32_t sequence;
    uint64_t timestamp;
};

/* Proof structure */
struct crypto_proof {
    uint64_t magic;
    uint64_t timestamp;
    uint64_t address;
    uint32_t device_id;
    uint32_t sequence;
    uint8_t hash[32];
    uint8_t signature[64];
};

/* Device structure */
struct device {
    uint32_t id;
    enum device_state state;
    uint32_t violation_count;
    pthread_mutex_t lock;
};

/* Global fuzzing state */
static struct cacheline *g_cachelines;
static struct shadow *g_shadows;
static struct crypto_proof *g_proofs;
static struct device g_devices[MAX_DEVICES];
static uint32_t g_crash_count = 0;
static uint32_t g_violation_count = 0;

/* Statistics */
struct fuzz_stats {
    uint64_t total_iterations;
    uint64_t crashes;
    uint64_t hangs;
    uint64_t violations;
    uint64_t state_errors;
    uint64_t race_conditions;
    uint64_t interesting_cases;
};

static struct fuzz_stats g_stats = {0};

/* Simple hash function */
static uint32_t compute_hash(const uint8_t *data, size_t len) {
    uint32_t hash = 0x12345678;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

/* Get timestamp in nanoseconds */
static uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Initialize fuzzing environment */
static int init_fuzzing_env(void) {
    /* Allocate shared memory for cachelines */
    g_cachelines = mmap(NULL, sizeof(struct cacheline) * SHADOW_MAP_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_cachelines == MAP_FAILED) {
        perror("mmap cachelines");
        return -1;
    }

    /* Allocate shadow map */
    g_shadows = mmap(NULL, sizeof(struct shadow) * SHADOW_MAP_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_shadows == MAP_FAILED) {
        perror("mmap shadows");
        return -1;
    }

    /* Allocate proof map */
    g_proofs = mmap(NULL, sizeof(struct crypto_proof) * PROOF_MAP_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_proofs == MAP_FAILED) {
        perror("mmap proofs");
        return -1;
    }

    /* Initialize devices */
    for (int i = 0; i < MAX_DEVICES; i++) {
        g_devices[i].id = i;
        g_devices[i].state = DEVICE_OFFLINE;
        g_devices[i].violation_count = 0;
        pthread_mutex_init(&g_devices[i].lock, NULL);
    }

    /* Initialize cachelines */
    for (int i = 0; i < SHADOW_MAP_SIZE; i++) {
        g_cachelines[i].state = CACHE_INVALID;
        g_cachelines[i].device_id = 0;
        g_cachelines[i].sequence = 0;
        pthread_mutex_init(&g_cachelines[i].lock, NULL);
    }

    return 0;
}

/* Cleanup fuzzing environment */
static void cleanup_fuzzing_env(void) {
    if (g_cachelines != MAP_FAILED) {
        munmap(g_cachelines, sizeof(struct cacheline) * SHADOW_MAP_SIZE);
    }
    if (g_shadows != MAP_FAILED) {
        munmap(g_shadows, sizeof(struct shadow) * SHADOW_MAP_SIZE);
    }
    if (g_proofs != MAP_FAILED) {
        munmap(g_proofs, sizeof(struct crypto_proof) * PROOF_MAP_SIZE);
    }
}

/* Simulate MESI state transition */
static int transition_state(struct cacheline *cl, enum cache_state new_state, uint32_t device_id) {
    pthread_mutex_lock(&cl->lock);

    enum cache_state old_state = cl->state;

    /* Validate transition */
    if (old_state == CACHE_INVALID && new_state == CACHE_MODIFIED) {
        /* Invalid transition */
        pthread_mutex_unlock(&cl->lock);
        g_stats.state_errors++;
        return -1;
    }

    /* Check exclusive ownership */
    if (new_state == CACHE_EXCLUSIVE || new_state == CACHE_MODIFIED) {
        if (cl->device_id != 0 && cl->device_id != device_id) {
            /* Ownership violation */
            pthread_mutex_unlock(&cl->lock);
            g_stats.violations++;
            return -1;
        }
    }

    cl->state = new_state;
    cl->device_id = device_id;
    cl->sequence++;

    pthread_mutex_unlock(&cl->lock);
    return 0;
}

/* Install shadow before granting exclusive access */
static int install_shadow(uint64_t addr_idx, struct cacheline *cl) {
    if (addr_idx >= SHADOW_MAP_SIZE) {
        return -1;
    }

    struct shadow *s = &g_shadows[addr_idx];

    /* Copy current data */
    memcpy(s->data, cl->data, CACHELINE_SIZE);
    s->hash = compute_hash(s->data, CACHELINE_SIZE);
    s->sequence = cl->sequence;
    s->timestamp = get_timestamp_ns();

    return 0;
}

/* Generate cryptographic proof */
static int generate_proof(uint64_t addr, uint32_t device_id,
                         const uint8_t *old_data, const uint8_t *new_data,
                         struct crypto_proof *proof) {
    proof->magic = 0xDEADBEEFCAFEBABE;
    proof->timestamp = get_timestamp_ns();
    proof->address = addr;
    proof->device_id = device_id;
    proof->sequence = 0;

    /* Compute hash of old || new */
    uint8_t combined[CACHELINE_SIZE * 2];
    memcpy(combined, old_data, CACHELINE_SIZE);
    memcpy(combined + CACHELINE_SIZE, new_data, CACHELINE_SIZE);

    uint32_t hash = compute_hash(combined, sizeof(combined));
    memcpy(proof->hash, &hash, sizeof(hash));

    /* Simple HMAC simulation */
    memcpy(proof->signature, proof->hash, 32);
    memcpy(proof->signature + 32, &proof->timestamp, sizeof(proof->timestamp));

    return 0;
}

/* Validate proof */
static int validate_proof(const struct crypto_proof *proof) {
    if (proof->magic != 0xDEADBEEFCAFEBABE) {
        return -1;
    }

    if (proof->timestamp == 0) {
        return -1;
    }

    /* Additional validation would go here */
    return 0;
}

/* Thread function for concurrent access */
struct thread_args {
    uint32_t device_id;
    uint64_t addr_idx;
    uint8_t operation; /* 0=read, 1=write */
    uint8_t *payload;
};

static void *concurrent_access_thread(void *arg) {
    struct thread_args *args = (struct thread_args *)arg;
    struct cacheline *cl = &g_cachelines[args->addr_idx % SHADOW_MAP_SIZE];

    for (int i = 0; i < 100; i++) {
        if (args->operation == 0) {
            /* Read */
            pthread_mutex_lock(&cl->lock);
            volatile uint8_t tmp = cl->data[i % CACHELINE_SIZE];
            (void)tmp;
            pthread_mutex_unlock(&cl->lock);
        } else {
            /* Write */
            pthread_mutex_lock(&cl->lock);
            cl->data[i % CACHELINE_SIZE] ^= args->payload[i % CACHELINE_SIZE];
            pthread_mutex_unlock(&cl->lock);
        }
    }

    return NULL;
}

/* Execute fuzzing strategy */
static int execute_fuzz_strategy(const struct fuzz_input *input) {
    uint64_t addr_idx = input->target_addr % SHADOW_MAP_SIZE;
    struct cacheline *cl = &g_cachelines[addr_idx];

    switch (input->strategy % FUZZ_NUM_STRATEGIES) {
        case FUZZ_RANDOM: {
            /* Random state transitions */
            enum cache_state new_state = input->target_state % 4;
            return transition_state(cl, new_state, input->device_id);
        }

        case FUZZ_RACE_CONDITION: {
            /* Create race condition with multiple threads */
            pthread_t threads[MAX_CONCURRENT];
            struct thread_args args[MAX_CONCURRENT];
            uint8_t num_threads = (input->concurrent_devices % MAX_CONCURRENT) + 1;

            for (int i = 0; i < num_threads; i++) {
                args[i].device_id = (input->device_id + i) % MAX_DEVICES;
                args[i].addr_idx = addr_idx;
                args[i].operation = i % 2;
                args[i].payload = (uint8_t *)input->payload;

                pthread_create(&threads[i], NULL, concurrent_access_thread, &args[i]);
            }

            for (int i = 0; i < num_threads; i++) {
                pthread_join(threads[i], NULL);
            }

            g_stats.race_conditions++;
            break;
        }

        case FUZZ_INVALID_STATE: {
            /* Try invalid state transition: Invalid -> Modified */
            pthread_mutex_lock(&cl->lock);
            cl->state = CACHE_INVALID;
            pthread_mutex_unlock(&cl->lock);

            int ret = transition_state(cl, CACHE_MODIFIED, input->device_id);
            if (ret < 0) {
                g_stats.interesting_cases++;
            }
            return ret;
        }

        case FUZZ_MALFORMED_PROOF: {
            /* Generate and validate malformed proof */
            struct crypto_proof proof;
            generate_proof(input->target_addr, input->device_id,
                          input->payload, input->payload, &proof);

            /* Corrupt proof */
            proof.magic = 0xBADBADBADBADBAD;

            int ret = validate_proof(&proof);
            if (ret < 0) {
                g_stats.interesting_cases++;
            }
            return ret;
        }

        case FUZZ_CONCURRENT_ACCESS: {
            /* Multiple devices access same cacheline */
            for (uint8_t i = 0; i < input->concurrent_devices && i < MAX_DEVICES; i++) {
                transition_state(cl, CACHE_SHARED, i);
            }
            break;
        }

        case FUZZ_BOUNDARY: {
            /* Test boundary addresses */
            uint64_t boundary_addrs[] = {
                0, 0xFFFFFFFFFFFFFFFF, 0x8000000000000000,
                SHADOW_MAP_SIZE - 1, SHADOW_MAP_SIZE, SHADOW_MAP_SIZE + 1
            };

            for (size_t i = 0; i < sizeof(boundary_addrs) / sizeof(boundary_addrs[0]); i++) {
                uint64_t idx = boundary_addrs[i] % SHADOW_MAP_SIZE;
                transition_state(&g_cachelines[idx], CACHE_SHARED, input->device_id);
            }
            break;
        }

        case FUZZ_MEMORY_CORRUPTION: {
            /* Try to corrupt memory */
            pthread_mutex_lock(&cl->lock);
            memcpy(cl->data, input->payload, CACHELINE_SIZE);

            /* Try to overflow */
            if (input->payload[0] > 200) {
                /* This would overflow in vulnerable code */
                size_t overflow_size = CACHELINE_SIZE + input->payload[0];
                if (overflow_size < 4096) {  /* Prevent massive overflows */
                    memset(cl->data, 0xAA, overflow_size);
                }
            }
            pthread_mutex_unlock(&cl->lock);
            break;
        }

        case FUZZ_INTEGER_OVERFLOW: {
            /* Test integer overflow scenarios */
            uint32_t large_val = 0xFFFFFFFF;
            uint32_t overflow = large_val + input->payload[0];

            cl->sequence = overflow;

            /* Test with shadow */
            install_shadow(addr_idx, cl);
            break;
        }

        case FUZZ_STATE_MACHINE: {
            /* Rapid state transitions to stress state machine */
            enum cache_state states[] = {
                CACHE_INVALID, CACHE_SHARED, CACHE_EXCLUSIVE,
                CACHE_MODIFIED, CACHE_SHARED, CACHE_INVALID
            };

            for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
                transition_state(cl, states[i], input->device_id);
            }
            break;
        }

        case FUZZ_PROTOCOL_VIOLATION: {
            /* Violate CXL protocol rules */
            /* Try to grant exclusive to two devices simultaneously */
            transition_state(cl, CACHE_EXCLUSIVE, input->device_id);
            int ret = transition_state(cl, CACHE_EXCLUSIVE,
                                      (input->device_id + 1) % MAX_DEVICES);
            if (ret < 0) {
                g_stats.violations++;
            }
            break;
        }

        case FUZZ_DOUBLE_FREE: {
            /* Simulate double-free scenario */
            install_shadow(addr_idx, cl);
            /* Try to install shadow again without exclusive grant */
            install_shadow(addr_idx, cl);
            break;
        }

        case FUZZ_USE_AFTER_FREE: {
            /* Simulate use-after-free */
            pthread_mutex_lock(&cl->lock);
            cl->state = CACHE_INVALID;
            uint32_t device_id = cl->device_id;
            pthread_mutex_unlock(&cl->lock);

            /* Try to use data after invalidation */
            volatile uint8_t tmp = g_cachelines[addr_idx].data[0];
            (void)tmp;
            (void)device_id;
            break;
        }
    }

    return 0;
}

/* Main fuzzing loop */
int main(int argc, char **argv) {
    struct fuzz_input input;
    int ret;

    /* Initialize */
    if (init_fuzzing_env() < 0) {
        fprintf(stderr, "Failed to initialize fuzzing environment\n");
        return 1;
    }

    /* Read input */
    ssize_t bytes_read = read(STDIN_FILENO, &input, sizeof(input));
    if (bytes_read != sizeof(input)) {
        /* Generate random input if not provided */
        srand(time(NULL) ^ getpid());
        input.strategy = rand() % FUZZ_NUM_STRATEGIES;
        input.device_id = rand() % MAX_DEVICES;
        input.initial_state = rand() % 4;
        input.target_state = rand() % 4;
        input.concurrent_devices = (rand() % MAX_CONCURRENT) + 1;
        input.target_addr = rand() % (SHADOW_MAP_SIZE * 64);

        for (int i = 0; i < CACHELINE_SIZE; i++) {
            input.payload[i] = rand() % 256;
        }
    }

    g_stats.total_iterations++;

    /* Execute fuzzing */
    ret = execute_fuzz_strategy(&input);

    /* Cleanup */
    cleanup_fuzzing_env();

    /* Report interesting cases */
    if (ret < 0 || g_stats.interesting_cases > 0 || g_stats.violations > 0) {
        return 1;  /* Interesting case for AFL */
    }

    return 0;
}
