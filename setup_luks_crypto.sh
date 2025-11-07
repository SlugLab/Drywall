#!/bin/bash
# LUKS Setup Script with VirtIO Crypto Acceleration
# This script should be run INSIDE the VM

set -e

COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_RED='\033[0;31m'
COLOR_NC='\033[0m' # No Color

log_info() {
    echo -e "${COLOR_GREEN}[INFO]${COLOR_NC} $1"
}

log_warn() {
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_NC} $1"
}

log_error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_NC} $1"
}

# Configuration
ENCRYPTED_IMAGE="${1:-/root/encrypted_volume.img}"
ENCRYPTED_SIZE="${2:-1024}"  # Size in MB
ENCRYPTED_NAME="cxl_encrypted"
MOUNT_POINT="/mnt/encrypted"
PASSWORD_FILE="/root/.luks_password"

log_info "=== CXL Crypto-Accelerated LUKS Setup ==="
log_info "Encrypted image: $ENCRYPTED_IMAGE"
log_info "Size: ${ENCRYPTED_SIZE}MB"

# Step 1: Check if we're in a VM
log_info "Step 1: Checking environment..."
if ! lspci | grep -q "CXL"; then
    log_error "CXL device not found! Are you running inside the VM?"
    exit 1
fi
log_info "CXL device detected"

# Step 2: Install required packages
log_info "Step 2: Installing required packages..."
if ! command -v cryptsetup &> /dev/null; then
    log_warn "cryptsetup not found, installing..."
    apt-get update -qq
    apt-get install -y cryptsetup cryptsetup-bin linux-modules-extra-$(uname -r) &> /dev/null
fi
log_info "Required packages installed"

# Step 3: Load VirtIO crypto module
log_info "Step 3: Loading VirtIO crypto module..."
if ! lsmod | grep -q "virtio_crypto"; then
    modprobe virtio_crypto || log_warn "Could not load virtio_crypto module (might not be available)"
fi

# Check for crypto devices
if [ -c /dev/crypto ]; then
    log_info "Crypto device /dev/crypto found"
else
    log_warn "Crypto device not found, will use software crypto"
fi

# Step 4: List available crypto algorithms
log_info "Step 4: Checking available crypto algorithms..."
log_info "Hardware-accelerated algorithms:"
cat /proc/crypto | grep -E "^name|^driver|^module" | grep -A 2 "virtio" || log_warn "No virtio crypto algorithms found"

# Step 5: Create encrypted image if it doesn't exist
if [ -f "$ENCRYPTED_IMAGE" ]; then
    log_warn "Encrypted image already exists at $ENCRYPTED_IMAGE"
    read -p "Do you want to reformat it? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        log_info "Skipping image creation"
        SKIP_FORMAT=1
    fi
fi

if [ "$SKIP_FORMAT" != "1" ]; then
    log_info "Step 5: Creating encrypted image..."
    dd if=/dev/zero of="$ENCRYPTED_IMAGE" bs=1M count=$ENCRYPTED_SIZE status=progress

    # Generate or prompt for password
    log_info "Setting up LUKS encryption..."
    if [ ! -f "$PASSWORD_FILE" ]; then
        read -s -p "Enter encryption password: " PASSWORD
        echo
        read -s -p "Confirm password: " PASSWORD_CONFIRM
        echo

        if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
            log_error "Passwords do not match!"
            exit 1
        fi

        echo -n "$PASSWORD" > "$PASSWORD_FILE"
        chmod 600 "$PASSWORD_FILE"
        log_info "Password saved to $PASSWORD_FILE"
    fi

    # Format with LUKS using hardware crypto if available
    log_info "Formatting with LUKS (this may take a moment)..."
    cryptsetup luksFormat \
        --cipher aes-xts-plain64 \
        --key-size 512 \
        --hash sha256 \
        --pbkdf pbkdf2 \
        --iter-time 2000 \
        --batch-mode \
        "$ENCRYPTED_IMAGE" "$PASSWORD_FILE"

    log_info "LUKS formatting complete"
fi

# Step 6: Open the encrypted device
log_info "Step 6: Opening encrypted device..."
if [ -e "/dev/mapper/$ENCRYPTED_NAME" ]; then
    log_warn "Device already open, closing first..."
    cryptsetup luksClose "$ENCRYPTED_NAME" 2>/dev/null || true
fi

cryptsetup luksOpen "$ENCRYPTED_IMAGE" "$ENCRYPTED_NAME" --key-file "$PASSWORD_FILE"
log_info "Encrypted device opened as /dev/mapper/$ENCRYPTED_NAME"

# Step 7: Create filesystem if needed
if ! blkid "/dev/mapper/$ENCRYPTED_NAME" | grep -q "TYPE="; then
    log_info "Step 7: Creating ext4 filesystem..."
    mkfs.ext4 -q "/dev/mapper/$ENCRYPTED_NAME"
    log_info "Filesystem created"
else
    log_info "Step 7: Filesystem already exists"
fi

# Step 8: Mount the encrypted device
log_info "Step 8: Mounting encrypted device..."
mkdir -p "$MOUNT_POINT"
mount "/dev/mapper/$ENCRYPTED_NAME" "$MOUNT_POINT"
log_info "Encrypted device mounted at $MOUNT_POINT"

# Step 9: Display information
log_info "=== Setup Complete ==="
echo
log_info "Device Information:"
cryptsetup status "$ENCRYPTED_NAME" | grep -E "type:|cipher:|keysize:|device:"
echo
log_info "Mount Information:"
df -h "$MOUNT_POINT" | tail -1
echo
log_info "Crypto Statistics:"
dmsetup table "$ENCRYPTED_NAME"

# Step 10: Performance test (optional)
read -p "Do you want to run a performance test? (yes/no): " RUN_TEST
if [ "$RUN_TEST" == "yes" ]; then
    log_info "Running performance test..."

    log_info "Write test (100MB)..."
    sync
    WRITE_TIME=$(dd if=/dev/zero of="$MOUNT_POINT/test_write" bs=1M count=100 oflag=direct 2>&1 | grep -oP '\d+\.\d+ MB/s')
    log_info "Write speed: $WRITE_TIME"

    log_info "Read test (100MB)..."
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    READ_TIME=$(dd if="$MOUNT_POINT/test_write" of=/dev/null bs=1M iflag=direct 2>&1 | grep -oP '\d+\.\d+ MB/s')
    log_info "Read speed: $READ_TIME"

    rm -f "$MOUNT_POINT/test_write"
fi

echo
log_info "=== Usage Instructions ==="
echo "1. Your encrypted volume is mounted at: $MOUNT_POINT"
echo "2. Password file (keep secure!): $PASSWORD_FILE"
echo "3. To unmount: umount $MOUNT_POINT && cryptsetup luksClose $ENCRYPTED_NAME"
echo "4. To remount: cryptsetup luksOpen $ENCRYPTED_IMAGE $ENCRYPTED_NAME --key-file $PASSWORD_FILE"
echo "             mount /dev/mapper/$ENCRYPTED_NAME $MOUNT_POINT"
echo
log_info "Done!"
