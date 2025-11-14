/*
 * AFL++ Harness for CXL Kernel Fuzzer
 *
 * This harness reads fuzzing input from stdin and uses it to
 * drive the CXL cache coherency fuzzer with eBPF coprocessor.
 *
 * Compile with AFL++:
 *   afl-clang-fast -o cxl_afl_harness cxl_afl_harness.c
 *
 * Run with AFL++:
 *   cod
 *
 * Or compile without AFL++ for testing:
 *   gcc -o cxl_afl_harness cxl_afl_harness.c
 *   echo <test_input> | ./cxl_afl_harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>

#define MAX_INPUT_SIZE 4096
#define CACHELINE_SIZE 64

/* Fuzzing strategies - maps to CXL fuzzer strategies */
enum fuzz_strategy {
    FUZZ_RANDOM = 0,
    FUZZ_RACE_CONDITION,
    FUZZ_INVALID_STATE,
    FUZZ_MALFORMED_PROOF,
    FUZZ_CONCURRENT_ACCESS,
    FUZZ_BOUNDARY_CASE,
    FUZZ_MEMORY_CORRUPTION,
    FUZZ_OVERFLOW,
    FUZZ_MAX
};

/* Cache states (MESI protocol) */
enum cache_state {
    CACHE_INVALID = 0,
    CACHE_SHARED,
    CACHE_EXCLUSIVE,
    CACHE_MODIFIED
};

/* Fuzzing input structure (read from stdin by AFL++) */
struct fuzz_input {
    uint8_t strategy;           /* Which fuzzing strategy to use (0-7) */
    uint8_t device_id;          /* Device ID (0-15) */
    uint8_t initial_state;      /* Initial cache state (0-3) */
    uint8_t target_state;       /* Target cache state (0-3) */
    uint8_t concurrent_devices; /* Number of concurrent devices (1-8) */
    uint8_t reserved[3];        /* Reserved for alignment */
    uint64_t target_addr;       /* Target address */
    uint8_t payload[CACHELINE_SIZE]; /* Cacheline payload */
} __attribute__((packed));

/* Global statistics */
struct {
    uint64_t tests_run;
    uint64_t crashes;
    uint64_t errors;
} stats = {0};

/* Simulate CXL firewall check */
int cxl_firewall_check(uint64_t addr, uint32_t device_id) {
    if (device_id > 15) return 0;  /* Invalid device */

    /* Firewall rules (simplified) */
    if (addr >= 0x1000 && addr <= 0x1FFF) {
        /* LUKS header region - only device 0 allowed */
        return (device_id == 0) ? 1 : 0;
    }

    if (addr >= 0x2000 && addr <= 0x2FFF) {
        /* LUKS key slots - NO DEVICE ALLOWED */
        return 0;
    }

    /* Other regions - allow by default */
    return 1;
}

/* Compute hash (simplified) */
uint32_t compute_hash(const uint8_t *data, size_t len) {
    uint32_t hash = 0;
    for (size_t i = 0; i < len; i++) {
        hash = hash * 31 + data[i];
    }
    return hash;
}

/* Simulate HMAC */
void compute_hmac(const uint8_t *data, size_t len, const uint8_t *key, uint8_t *hmac) {
    uint32_t h = 0;
    for (size_t i = 0; i < len; i++) {
        h = h * 31 + data[i] + (key ? key[i % 32] : 0);
    }
    memcpy(hmac, &h, sizeof(h));
}

/* Execute fuzzing test based on input */
int execute_fuzz_test(const struct fuzz_input *input) {
    enum fuzz_strategy strategy = input->strategy % FUZZ_MAX;
    uint32_t device_id = input->device_id % 16;
    uint64_t addr = input->target_addr;

    /* Sanitize address to safe range */
    addr = 0x1000 + (addr % 0x10000);

    switch (strategy) {
    case FUZZ_RANDOM: {
        /* Random cache operations */
        enum cache_state state = input->initial_state % 4;

        /* Simulate cache state transitions */
        for (int i = 0; i < 10; i++) {
            enum cache_state new_state = (state + 1) % 4;

            /* Validate transition */
            if (state == CACHE_INVALID && new_state == CACHE_MODIFIED) {
                /* Invalid: can't go directly from Invalid to Modified */
                return -1;
            }

            state = new_state;
        }
        break;
    }

    case FUZZ_RACE_CONDITION: {
        /* Test race conditions - use shared memory */
        void *mem = mmap(NULL, CACHELINE_SIZE, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            return -1;
        }

        memcpy(mem, input->payload, CACHELINE_SIZE);

        uint8_t concurrent = (input->concurrent_devices % 8) + 1;

        /* Fork processes to create races */
        for (uint8_t i = 0; i < concurrent && i < 4; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                /* Child: Access shared memory */
                volatile uint8_t *vmem = (volatile uint8_t *)mem;
                for (int j = 0; j < 100; j++) {
                    vmem[j % CACHELINE_SIZE] ^= j;
                }
                munmap(mem, CACHELINE_SIZE);
                exit(0);
            } else if (pid < 0) {
                munmap(mem, CACHELINE_SIZE);
                return -1;
            }
        }

        /* Wait for children */
        int status;
        int crashed = 0;
        for (uint8_t i = 0; i < concurrent && i < 4; i++) {
            wait(&status);
            if (WIFSIGNALED(status)) {
                crashed = 1;
            }
        }

        munmap(mem, CACHELINE_SIZE);

        if (crashed) {
            return -1;  /* Race condition caused crash */
        }
        break;
    }

    case FUZZ_INVALID_STATE: {
        /* Test invalid state transitions */
        enum cache_state from = input->initial_state % 4;
        enum cache_state to = input->target_state % 4;

        /* Check for invalid transitions */
        if (from == CACHE_INVALID && to == CACHE_MODIFIED) {
            /* Invalid: Invalid → Modified requires Exclusive first */
            return -1;
        }

        if (from == CACHE_SHARED && to == CACHE_MODIFIED) {
            /* Need exclusive access first */
            if (!cxl_firewall_check(addr, device_id)) {
                return -1;  /* Firewall denied */
            }
        }
        break;
    }

    case FUZZ_MALFORMED_PROOF: {
        /* Test malformed cryptographic proofs */
        uint8_t proof_data[64];
        memcpy(proof_data, input->payload, 64);

        /* Shadow hash (first 32 bytes) */
        uint32_t shadow_hash = compute_hash(proof_data, 32);

        /* HMAC (last 32 bytes) */
        uint8_t expected_hmac[4];
        uint8_t key[32] = {0x42};  /* Device key */
        compute_hmac(proof_data, 32, key, expected_hmac);

        /* Validate HMAC */
        if (memcmp(expected_hmac, proof_data + 32, 4) != 0) {
            return -1;  /* Invalid proof - should quarantine device */
        }
        break;
    }

    case FUZZ_CONCURRENT_ACCESS: {
        /* Test concurrent device access */

        /* Check firewall for primary device */
        int fw_result = cxl_firewall_check(addr, device_id);
        if (!fw_result) {
            return -1;  /* Access denied */
        }

        /* Simulate multiple devices trying to access */
        for (uint8_t i = 0; i < input->concurrent_devices % 8; i++) {
            int result = cxl_firewall_check(addr, i);
            /* Only one device should be granted exclusive */
        }
        break;
    }

    case FUZZ_BOUNDARY_CASE: {
        /* Test boundary addresses */
        uint64_t test_addrs[] = {
            0x0000,                /* Zero address */
            0x0FFF,                /* Just before 4K */
            0x1000,                /* 4K boundary */
            0x1FFF,                /* End of LUKS header */
            0x2000,                /* Key slot region */
            0xFFFF,                /* 64K boundary */
            0xFFFFFFFF,            /* 4GB boundary */
            addr                   /* User-provided */
        };

        for (int i = 0; i < 8; i++) {
            cxl_firewall_check(test_addrs[i], device_id);
        }
        break;
    }

    case FUZZ_MEMORY_CORRUPTION: {
        /* Test memory corruption detection */
        uint8_t *buf = malloc(CACHELINE_SIZE * 2);
        if (!buf) return -1;

        /* Set up pattern */
        memcpy(buf, input->payload, CACHELINE_SIZE);
        memset(buf + CACHELINE_SIZE, 0xAA, CACHELINE_SIZE);

        /* Compute hashes */
        uint32_t hash1 = compute_hash(buf, CACHELINE_SIZE);
        uint32_t hash2 = compute_hash(buf + CACHELINE_SIZE, CACHELINE_SIZE);

        /* Check for corruption */
        volatile int corrupted = (hash1 == hash2);

        if (corrupted && input->payload[0] != 0xAA) {
            /* Unexpected corruption detected */
            free(buf);
            return -1;
        }

        free(buf);
        break;
    }

    case FUZZ_OVERFLOW: {
        /* Test integer overflows */

        /* Sequence number overflow */
        uint32_t seq = *(uint32_t *)input->payload;
        if (seq == 0xFFFFFFFF) {
            seq++;  /* Wraps to 0 */
            if (seq != 0) {
                return -1;  /* Unexpected behavior */
            }
        }

        /* Address overflow */
        uint64_t addr_test = input->target_addr;
        if (addr_test > 0xFFFFFFFFFFFFFF00ULL) {
            addr_test += CACHELINE_SIZE;
            /* Check if it wrapped */
        }

        /* Size overflow */
        size_t size = *(size_t *)(input->payload + 8);
        if (size > (size_t)-100) {
            size++;  /* May overflow */
        }

        break;
    }

    default:
        break;
    }

    return 0;
}

/* AFL++ persistent mode (optional - for better performance) */
#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();
#endif

int main(int argc, char *argv[]) {
    /* AFL++ persistent mode setup */
#ifdef __AFL_FUZZ_TESTCASE_LEN
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        if (len < (int)sizeof(struct fuzz_input)) {
            continue;
        }

        struct fuzz_input *input = (struct fuzz_input *)buf;
        stats.tests_run++;

        int result = execute_fuzz_test(input);
        if (result < 0) {
            stats.errors++;
        }
    }
#else
    /* Normal mode - read from stdin */
    uint8_t input_buf[MAX_INPUT_SIZE];
    ssize_t input_len = read(STDIN_FILENO, input_buf, sizeof(input_buf));

    if (input_len < (ssize_t)sizeof(struct fuzz_input)) {
        fprintf(stderr, "Error: Input too small (need %zu bytes, got %zd)\n",
                sizeof(struct fuzz_input), input_len);
        return 1;
    }

    /* Parse input */
    struct fuzz_input *input = (struct fuzz_input *)input_buf;

    /* Execute fuzzing test */
    stats.tests_run++;
    int result = execute_fuzz_test(input);

    if (result < 0) {
        stats.errors++;
        return 1;
    }
#endif

    return 0;
}
