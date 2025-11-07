# CXL Crypto Accelerator - LUKS Encryption Setup Complete

## What Was Done

I've successfully set up LUKS encryption with CXL crypto accelerator support in your VM disk image (`/root/CXLMemSim/build/qemu.img`). Here's what was configured:

### 1. Software Installation
- **cryptsetup 2.7.0** - LUKS encryption management
- **dm-crypt** - Device-mapper crypto target
- **dmsetup** - Device-mapper setup utility
- All dependencies and kernel modules

### 2. Scripts Installed (in `/root/` of VM)

| Script | Purpose |
|--------|---------|
| `setup_luks_crypto.sh` | Main LUKS setup with hardware acceleration detection |
| `init_luks.sh` | Automatic initialization (runs on first boot) |
| `crypto_benchmark.sh` | Performance testing suite |
| `mount_luks.sh` | Quick mount/unmount utility |
| `verify_crypto_accel.sh` | Hardware acceleration verification |
| `LUKS_README.txt` | Complete usage documentation |

### 3. Systemd Service
- **setup-luks-crypto.service** - Enabled to run on boot
- Will automatically initialize LUKS on next VM boot

## How to Use

### Start the VM

```bash
cd /root/Drywall/build
bash ../launch.sh
```

Or if you want to start without GDB:

```bash
# Edit launch.sh and remove 'gdb --args' from line 15
./qemu-system-x86_64 --enable-kvm -cpu host ...
```

### Inside the VM (First Boot)

The system will automatically:
1. Load crypto kernel modules
2. Create `/root/encrypted_volume.img` (1GB)
3. Format it with LUKS encryption
4. Mount it at `/mnt/encrypted`
5. Create test data

**Default Password:** `cxl_crypto_test`
**Password File:** `/root/.luks_password`

### Verify Setup

Once inside the VM, check the setup:

```bash
# View the README
cat /root/LUKS_README.txt

# Verify hardware crypto
bash /root/verify_crypto_accel.sh

# Check the setup log
cat /root/luks_setup.log

# View encrypted volume
ls -lh /root/encrypted_volume.img

# Check mount
df -h /mnt/encrypted
```

### Manual Operations

```bash
# Mount encrypted volume
bash /root/mount_luks.sh /root/encrypted_volume.img mount

# Unmount
bash /root/mount_luks.sh /root/encrypted_volume.img umount

# Check status
bash /root/mount_luks.sh /root/encrypted_volume.img status
```

### Performance Testing

```bash
# Run comprehensive benchmark
bash /root/crypto_benchmark.sh

# Quick test
dd if=/dev/urandom of=/mnt/encrypted/testfile bs=1M count=100
```

## CXL Device Information

The VM has:
- **PCI Bus:** 0d:00.0
- **Device:** Intel CXL Type1 device (0d93)
- **Features:** VirtIO crypto acceleration
- **Memory:** 256MB CXL memory backend

## Crypto Configuration

The LUKS setup uses:
- **Cipher:** AES-XTS-Plain64
- **Key Size:** 512 bits (AES-256)
- **Hash:** SHA-256
- **PBKDF:** PBKDF2 (2000ms iteration time)

## Hardware Acceleration

To verify hardware crypto acceleration is being used:

```bash
# Check for VirtIO crypto algorithms
cat /proc/crypto | grep virtio

# View crypto statistics
dmsetup table cxl_encrypted

# Monitor performance
iostat -x 1 /dev/mapper/cxl_encrypted
```

## Security Notes

⚠️ **IMPORTANT:**
- The default password is stored in `/root/.luks_password`
- This is for testing/development only
- For production use:
  - Change the password: `cryptsetup luksChangeKey /root/encrypted_volume.img`
  - Use proper key management
  - Consider using TPM or other hardware security modules

## Troubleshooting

### If the automatic setup didn't run:

```bash
# Check service status
systemctl status setup-luks-crypto.service

# View logs
journalctl -u setup-luks-crypto.service

# Run manually
bash /root/init_luks.sh
```

### If crypto acceleration isn't working:

```bash
# Check PCI devices
lspci | grep CXL

# Load modules
modprobe virtio_crypto
modprobe dm-crypt

# Check available algorithms
cat /proc/crypto
```

### If mount fails:

```bash
# Check if device is open
dmsetup ls

# Close and reopen
cryptsetup luksClose cxl_encrypted
cryptsetup luksOpen /root/encrypted_volume.img cxl_encrypted
mount /dev/mapper/cxl_encrypted /mnt/encrypted
```

## Files Created

Host system (`/root/Drywall/`):
- `setup_luks_crypto.sh` - Setup script
- `crypto_benchmark.sh` - Benchmark script
- `mount_luks.sh` - Mount utility
- `verify_crypto_accel.sh` - Verification script
- `LUKS_SETUP_COMPLETE.md` - This file

VM system (`/root/CXLMemSim/build/qemu.img`):
- `/root/setup_luks_crypto.sh`
- `/root/init_luks.sh`
- `/root/crypto_benchmark.sh`
- `/root/mount_luks.sh`
- `/root/verify_crypto_accel.sh`
- `/root/LUKS_README.txt`
- `/etc/systemd/system/setup-luks-crypto.service`

## Next Steps

1. **Boot the VM**
   ```bash
   cd /root/Drywall/build
   bash ../launch.sh
   ```

2. **Wait for automatic setup** (or press Enter to skip if systemd delays)

3. **Verify** the encrypted volume is mounted:
   ```bash
   df -h /mnt/encrypted
   ls -la /mnt/encrypted
   ```

4. **Test** the crypto acceleration:
   ```bash
   bash /root/crypto_benchmark.sh
   ```

5. **Use** the encrypted volume for your data

## Additional Information

- The encrypted volume persists across reboots
- You'll need to mount it manually after each reboot (or configure auto-mount in /etc/fstab)
- The password is saved for convenience but should be changed for security
- All scripts have built-in help and error checking

---

**Setup completed:** November 3, 2025
**VM Image:** `/root/CXLMemSim/build/qemu.img`
**Ready to use!** 🎉
