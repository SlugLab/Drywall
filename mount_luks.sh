#!/bin/bash
# Quick script to mount/unmount LUKS encrypted volume

set -e

ENCRYPTED_IMAGE="${1:-/root/encrypted_volume.img}"
ENCRYPTED_NAME="cxl_encrypted"
MOUNT_POINT="/mnt/encrypted"
PASSWORD_FILE="/root/.luks_password"

ACTION="${2:-mount}"

if [ "$ACTION" == "mount" ]; then
    echo "[INFO] Mounting encrypted volume..."

    # Check if already mounted
    if mountpoint -q "$MOUNT_POINT"; then
        echo "[INFO] Already mounted at $MOUNT_POINT"
        exit 0
    fi

    # Open LUKS device
    if [ ! -e "/dev/mapper/$ENCRYPTED_NAME" ]; then
        if [ -f "$PASSWORD_FILE" ]; then
            cryptsetup luksOpen "$ENCRYPTED_IMAGE" "$ENCRYPTED_NAME" --key-file "$PASSWORD_FILE"
        else
            cryptsetup luksOpen "$ENCRYPTED_IMAGE" "$ENCRYPTED_NAME"
        fi
    fi

    # Mount
    mkdir -p "$MOUNT_POINT"
    mount "/dev/mapper/$ENCRYPTED_NAME" "$MOUNT_POINT"

    echo "[INFO] Mounted at $MOUNT_POINT"
    df -h "$MOUNT_POINT"

elif [ "$ACTION" == "umount" ] || [ "$ACTION" == "unmount" ]; then
    echo "[INFO] Unmounting encrypted volume..."

    # Unmount
    if mountpoint -q "$MOUNT_POINT"; then
        umount "$MOUNT_POINT"
    fi

    # Close LUKS device
    if [ -e "/dev/mapper/$ENCRYPTED_NAME" ]; then
        cryptsetup luksClose "$ENCRYPTED_NAME"
    fi

    echo "[INFO] Unmounted and closed"

elif [ "$ACTION" == "status" ]; then
    echo "[INFO] Encrypted volume status:"

    if [ -e "/dev/mapper/$ENCRYPTED_NAME" ]; then
        cryptsetup status "$ENCRYPTED_NAME"
        echo
    else
        echo "Device is not open"
    fi

    if mountpoint -q "$MOUNT_POINT"; then
        echo "Mounted at: $MOUNT_POINT"
        df -h "$MOUNT_POINT"
    else
        echo "Not mounted"
    fi

else
    echo "Usage: $0 [encrypted_image] [mount|umount|status]"
    echo "Example: $0 /root/encrypted_volume.img mount"
    exit 1
fi
