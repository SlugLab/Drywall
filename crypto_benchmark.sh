#!/bin/bash
# Crypto Performance Benchmark Script
# Compares software vs hardware crypto acceleration

set -e

COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_BLUE='\033[0;34m'
COLOR_NC='\033[0m'

log_info() {
    echo -e "${COLOR_GREEN}[INFO]${COLOR_NC} $1"
}

log_test() {
    echo -e "${COLOR_BLUE}[TEST]${COLOR_NC} $1"
}

RESULTS_FILE="/tmp/crypto_benchmark_results.txt"
TEST_SIZE=512  # MB

log_info "=== CXL Crypto Accelerator Benchmark ==="
date > "$RESULTS_FILE"

# Check crypto devices
log_info "Checking crypto devices..."
echo "=== Crypto Devices ===" >> "$RESULTS_FILE"
lspci | grep -i cxl >> "$RESULTS_FILE" || echo "No CXL devices" >> "$RESULTS_FILE"
cat /proc/crypto | grep -E "^name|^driver|^module|^priority" >> "$RESULTS_FILE"

# Function to run encryption test
run_encryption_test() {
    local TEST_NAME=$1
    local CIPHER=$2
    local KEYSIZE=$3
    local IMAGE=$4

    log_test "Testing: $TEST_NAME"

    # Create test image
    dd if=/dev/zero of="$IMAGE" bs=1M count=$TEST_SIZE 2>/dev/null

    # Format with LUKS
    echo -n "testpass" | cryptsetup luksFormat \
        --cipher "$CIPHER" \
        --key-size "$KEYSIZE" \
        --hash sha256 \
        --pbkdf pbkdf2 \
        --batch-mode \
        "$IMAGE" - 2>/dev/null

    # Open device
    echo -n "testpass" | cryptsetup luksOpen "$IMAGE" "test_$TEST_NAME" - 2>/dev/null

    # Create filesystem
    mkfs.ext4 -q "/dev/mapper/test_$TEST_NAME" 2>/dev/null

    # Mount
    mkdir -p "/mnt/test_$TEST_NAME"
    mount "/dev/mapper/test_$TEST_NAME" "/mnt/test_$TEST_NAME"

    # Write test
    log_test "Write test..."
    sync
    WRITE_START=$(date +%s.%N)
    dd if=/dev/zero of="/mnt/test_$TEST_NAME/testfile" bs=1M count=$TEST_SIZE oflag=direct 2>/dev/null
    sync
    WRITE_END=$(date +%s.%N)
    WRITE_TIME=$(echo "$WRITE_END - $WRITE_START" | bc)
    WRITE_SPEED=$(echo "scale=2; $TEST_SIZE / $WRITE_TIME" | bc)

    # Read test
    log_test "Read test..."
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    READ_START=$(date +%s.%N)
    dd if="/mnt/test_$TEST_NAME/testfile" of=/dev/null bs=1M iflag=direct 2>/dev/null
    READ_END=$(date +%s.%N)
    READ_TIME=$(echo "$READ_END - $READ_START" | bc)
    READ_SPEED=$(echo "scale=2; $TEST_SIZE / $READ_TIME" | bc)

    # Cleanup
    umount "/mnt/test_$TEST_NAME"
    cryptsetup luksClose "test_$TEST_NAME"
    rm -f "$IMAGE"

    # Record results
    echo "=== $TEST_NAME ===" >> "$RESULTS_FILE"
    echo "Cipher: $CIPHER-$KEYSIZE" >> "$RESULTS_FILE"
    echo "Write Speed: ${WRITE_SPEED} MB/s (${WRITE_TIME}s)" >> "$RESULTS_FILE"
    echo "Read Speed: ${READ_SPEED} MB/s (${READ_TIME}s)" >> "$RESULTS_FILE"
    echo >> "$RESULTS_FILE"

    log_info "$TEST_NAME Results: Write ${WRITE_SPEED} MB/s, Read ${READ_SPEED} MB/s"
}

# Test 1: AES-256 XTS (most common)
log_info "Test 1: AES-256-XTS"
run_encryption_test "aes256xts" "aes-xts-plain64" "512" "/tmp/test_aes256.img"

# Test 2: AES-128 XTS (faster)
log_info "Test 2: AES-128-XTS"
run_encryption_test "aes128xts" "aes-xts-plain64" "256" "/tmp/test_aes128.img"

# Test 3: AES-256 CBC (for comparison)
log_info "Test 3: AES-256-CBC"
run_encryption_test "aes256cbc" "aes-cbc-plain" "256" "/tmp/test_aes256cbc.img"

# Display summary
log_info "=== Benchmark Complete ==="
echo
cat "$RESULTS_FILE"
echo
log_info "Full results saved to: $RESULTS_FILE"

# Check if hardware acceleration was used
log_info "Checking crypto usage..."
cat /proc/crypto | grep -A 10 "virtio" || log_info "No virtio crypto stats available"
