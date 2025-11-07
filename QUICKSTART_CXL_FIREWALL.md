# CXL Firewall Quick Start Guide

## 5-Minute Setup

### Step 1: Build eBPF Program (2 minutes)

```bash
cd /root/Drywall/tools/ebpf

# Build the eBPF coprocessor
make -f Makefile.ebpf.cxl clean all

# Verify build
ls -lh cxl_firewall.bpf.o
```

**Expected Output:**
```
-rw-r--r-- 1 root root 15K Nov 7 12:00 cxl_firewall.bpf.o
```

### Step 2: Load Firewall (1 minute)

```bash
cd /root/Drywall

# Load eBPF program (requires root)
sudo ./cxl_firewall_ctl.py load tools/ebpf/cxl_firewall.bpf.o

# Configure basic policies
sudo ./cxl_firewall_ctl.py add-policy \
    --start 0xffffffff80000000 \
    --end 0xffffffff84000000 \
    --require-shadow
```

### Step 3: Run Tests (2 minutes)

```bash
# Run test suite
./test_cxl_firewall.sh
```

**Expected Output:**
```
CXL Firewall Integration Test Suite
====================================

TEST: Checking prerequisites
[INFO] ✓ PASS: clang found
[INFO] ✓ PASS: python3 found
...

TEST SUMMARY
Tests passed: 10/12
```

## Quick Fault Injection Demo

### Setup Test VM

```bash
# Launch QEMU with CXL device (in one terminal)
./launch.sh
```

### Run Fuzzer (in another terminal)

```bash
# Quick fuzzing test
./cxl_kernel_fuzzer.py --iterations 1

# View results
cat fuzz_results.json
```

## Monitoring Live Operations

```bash
# Terminal 1: Monitor shadow cache
watch -n 1 'sudo ./cxl_firewall_ctl.py stats'

# Terminal 2: Monitor events
sudo ./cxl_firewall_ctl.py monitor --duration 60

# Terminal 3: Run workload in VM (via SSH)
ssh -p 2222 root@localhost "dd if=/dev/zero of=/mnt/encrypted/test bs=1M count=100"
```

## Common Commands Cheat Sheet

### Policy Management

```bash
# Add policy
sudo ./cxl_firewall_ctl.py add-policy --start ADDR --end ADDR [--allow-exclusive] [--require-shadow]

# View statistics
sudo ./cxl_firewall_ctl.py stats [--json]

# Dump shadow cache
sudo ./cxl_firewall_ctl.py dump-shadow [--json]
```

### Fault Injection

```bash
# Enable fault injection
sudo ./cxl_firewall_ctl.py fault-inject --enable --rate 10 --type 1

# Disable fault injection
sudo ./cxl_firewall_ctl.py fault-inject --disable
```

### Fuzzing

```bash
# Full campaign
./cxl_kernel_fuzzer.py --iterations 5 --output results.json

# Specific scenario
./cxl_kernel_fuzzer.py --scenario DELAYED_REVOKE --iterations 10

# Quick test
./cxl_kernel_fuzzer.py --iterations 1
```

## Fault Scenarios

| Scenario | Description | Severity |
|----------|-------------|----------|
| `DELAYED_REVOKE` | Device delays response to revoke > timeout | Medium |
| `SILENT_DROP` | Device drops transactions without response | High |
| `CORRUPT_DATA` | Device corrupts cacheline data | Critical |
| `STATE_VIOLATION` | Invalid coherence state transition | High |
| `HOT_UNPLUG` | Device unplugs while holding exclusive | Critical |

## Expected Results

### Healthy System

```json
{
  "total_transactions": 12543,
  "exclusive_grants": 342,
  "exclusive_revokes": 338,
  "policy_violations": 0,
  "shadow_creates": 215,
  "shadow_restores": 0,
  "faults_injected": 0
}
```

### Under Fault Injection

```json
{
  "total_transactions": 8921,
  "exclusive_grants": 234,
  "exclusive_revokes": 198,
  "policy_violations": 5,
  "shadow_creates": 187,
  "shadow_restores": 36,
  "faults_injected": 89
}
```

**Key Indicators:**
- `shadow_restores > 0`: Recovery mechanisms working
- `policy_violations == 0`: No unauthorized access
- `exclusive_grants ≈ exclusive_revokes`: Normal operation

## Troubleshooting

### "bpftool not found"

```bash
# Ubuntu/Debian
sudo apt-get install linux-tools-$(uname -r) linux-tools-generic

# Fedora/RHEL
sudo dnf install bpftool
```

### "Failed to load eBPF program"

```bash
# Check kernel version (need 5.10+)
uname -r

# Check BPF support
zgrep CONFIG_BPF /proc/config.gz

# Try with verbose output
sudo ./cxl_firewall_ctl.py load tools/ebpf/cxl_firewall.bpf.o -v
```

### "Cannot connect to QEMU monitor"

```bash
# Check QEMU is running
ps aux | grep qemu

# Verify monitor socket
ls -l /tmp/qemu-monitor.sock

# Update fuzzer configuration
./cxl_kernel_fuzzer.py --qemu-monitor /path/to/monitor.sock
```

## Next Steps

1. **Read Full Documentation**: See `CXL_FIREWALL_README.md`
2. **Experiment with Policies**: Try different protection scenarios
3. **Run Comprehensive Fuzzing**: Increase iteration count
4. **Analyze Results**: Study recovery patterns and failure modes
5. **Extend Framework**: Add custom fault scenarios

## Performance Tips

### For Development/Testing

```bash
# Enable verbose logging
export QEMU_LOG_LEVEL=debug

# Increase shadow cache capacity (in cxl_firewall.bpf.c)
#define MAX_CACHELINES 131072  /* 8MB worth */
```

### For Production

```bash
# Disable fault injection
sudo ./cxl_firewall_ctl.py fault-inject --disable

# Enable only critical policies
# (protect kernel, allow user memory)

# Monitor shadow cache usage
watch -n 5 'sudo ./cxl_firewall_ctl.py stats | grep shadow'
```

## Getting Help

- Check logs: `dmesg | grep -i cxl`
- View eBPF verifier output: `sudo bpftool prog show`
- Run tests: `./test_cxl_firewall.sh`
- See full docs: `CXL_FIREWALL_README.md`

## Files Reference

| File | Purpose |
|------|---------|
| `tools/ebpf/cxl_firewall.bpf.c` | eBPF coprocessor |
| `ebpf/cxl_firewall.c` | QEMU integration |
| `hw/cxl/cxl-fault-injection.c` | Fault injection framework |
| `cxl_firewall_ctl.py` | Control plane tool |
| `cxl_kernel_fuzzer.py` | Fuzzing harness |
| `test_cxl_firewall.sh` | Test suite |
| `CXL_FIREWALL_README.md` | Full documentation |
