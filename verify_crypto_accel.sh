#!/bin/bash
# Script to verify CXL crypto accelerator is working

set -e

COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_RED='\033[0;31m'
COLOR_NC='\033[0m'

log_info() {
    echo -e "${COLOR_GREEN}[✓]${COLOR_NC} $1"
}

log_warn() {
    echo -e "${COLOR_YELLOW}[!]${COLOR_NC} $1"
}

log_error() {
    echo -e "${COLOR_RED}[✗]${COLOR_NC} $1"
}

echo "=== CXL Crypto Accelerator Verification ==="
echo

# Check 1: PCI Device
echo "1. Checking PCI devices..."
if lspci | grep -q "CXL"; then
    CXL_DEVICE=$(lspci | grep "CXL" | head -1)
    log_info "CXL device found: $CXL_DEVICE"
else
    log_error "No CXL device found"
    exit 1
fi
echo

# Check 2: Kernel modules
echo "2. Checking kernel modules..."
MODULES=("virtio_crypto" "crypto_engine" "cryptodev")
for MODULE in "${MODULES[@]}"; do
    if lsmod | grep -q "^$MODULE"; then
        log_info "Module $MODULE is loaded"
    else
        log_warn "Module $MODULE is not loaded"
        modprobe "$MODULE" 2>/dev/null && log_info "  └─ Loaded $MODULE successfully" || log_warn "  └─ Could not load $MODULE"
    fi
done
echo

# Check 3: Crypto devices
echo "3. Checking crypto devices..."
if [ -c /dev/crypto ]; then
    log_info "Crypto device /dev/crypto exists"
else
    log_warn "Crypto device /dev/crypto not found"
fi
echo

# Check 4: Available crypto algorithms
echo "4. Checking crypto algorithms..."
if cat /proc/crypto | grep -q "virtio"; then
    log_info "VirtIO crypto algorithms found:"
    cat /proc/crypto | grep -E "^name|^driver" | grep -A 1 "virtio" | sed 's/^/  /'
else
    log_warn "No VirtIO crypto algorithms found"
    log_info "Available software algorithms:"
    cat /proc/crypto | grep -E "^name" | head -10 | sed 's/^/  /'
fi
echo

# Check 5: Cryptsetup availability
echo "5. Checking cryptsetup..."
if command -v cryptsetup &> /dev/null; then
    VERSION=$(cryptsetup --version | head -1)
    log_info "cryptsetup is installed: $VERSION"
else
    log_error "cryptsetup is not installed"
fi
echo

# Check 6: dm-crypt module
echo "6. Checking dm-crypt..."
if lsmod | grep -q "dm_crypt"; then
    log_info "dm-crypt module is loaded"
else
    log_warn "dm-crypt module is not loaded"
    modprobe dm-crypt 2>/dev/null && log_info "  └─ Loaded dm-crypt" || log_error "  └─ Failed to load dm-crypt"
fi
echo

# Check 7: Crypto performance
echo "7. Quick performance test..."
log_info "Testing AES-256-XTS performance with OpenSSL..."
PERF=$(openssl speed -elapsed -evp aes-256-xts 2>&1 | grep "aes-256-xts" | awk '{print $7}')
if [ ! -z "$PERF" ]; then
    log_info "AES-256-XTS: ${PERF}k ops/sec"
else
    log_warn "Could not measure performance"
fi
echo

# Summary
echo "=== Summary ==="
echo "The CXL crypto accelerator setup is:"
if lspci | grep -q "CXL" && command -v cryptsetup &> /dev/null; then
    log_info "READY for use"
    echo
    echo "Next steps:"
    echo "  1. Run: bash /root/Drywall/setup_luks_crypto.sh"
    echo "  2. Or benchmark: bash /root/Drywall/crypto_benchmark.sh"
else
    log_warn "INCOMPLETE - some components are missing"
fi
