# CXL Device Hot-Unplug and Fault Injection Guide

## Overview

This guide covers how to emulate CXL device hot-unplug events and inject faults in QEMU for testing system resilience.

## Prerequisites

### 1. QEMU Configuration

Your QEMU instance must be started with the QMP (QEMU Machine Protocol) or HMP (Human Monitor Protocol) interface enabled:

```bash
# Add to QEMU command line:
-monitor tcp:127.0.0.1:1234,server,nowait

# Or for QMP (JSON-based):
-qmp tcp:127.0.0.1:4444,server,nowait
```

### 2. Device Setup

The CXL device must be hotpluggable. In your `launch_vm_nogdb.sh`, the device is already set up correctly:

```bash
-device cxl-type1,bus=root_port13,memdev=cxl-mem1,lsa=cxl-lsa1,id=cxl-type1-0
```

The `id=cxl-type1-0` parameter is crucial for hot-unplug operations.

## Hot-Unplug Methods

### Method 1: Using the Test Script

The `cxl_hotplug_test.sh` script provides an interactive interface:

```bash
# Automatic test mode
bash cxl_hotplug_test.sh auto

# Interactive mode
bash cxl_hotplug_test.sh
```

### Method 2: Manual QEMU Monitor Commands

#### Connect to QEMU Monitor

```bash
# Using netcat
nc localhost 1234

# Or using telnet
telnet localhost 1234
```

#### Basic Hot-Unplug Sequence

```
(qemu) info pci
# Find your CXL device (look for bus 0d:00.0)

(qemu) device_del cxl-type1-0
# Device is now being removed

(qemu) info pci
# Verify device is gone
```

#### Hot-Plug Back

```
(qemu) device_add cxl-type1,id=cxl-type1-0,bus=root_port13,memdev=cxl-mem1,lsa=cxl-lsa1
# Device is added back
```

## Fault Injection Methods

### 1. PCIe AER (Advanced Error Reporting) Injection

QEMU supports PCIe AER error injection for testing error handling:

#### Correctable Errors

```
(qemu) pcie_aer_inject_error -c id=cxl-type1-0,error=COR_INTERNAL
```

Available correctable errors:
- `COR_INTERNAL` - Internal error
- `COR_BAD_TLP` - Bad TLP
- `COR_BAD_DLLP` - Bad DLLP
- `COR_REPLAY_TIMER` - Replay timer timeout
- `COR_REPLAY_ROLLOVER` - Replay rollover

#### Uncorrectable Non-Fatal Errors

```
(qemu) pcie_aer_inject_error -u id=cxl-type1-0,error=UNCOR_POISON_TLP
```

Available uncorrectable errors:
- `UNCOR_POISON_TLP` - Poisoned TLP
- `UNCOR_UNSUPPORTED` - Unsupported request
- `UNCOR_ECRC` - ECRC error
- `UNCOR_MALFORMED_TLP` - Malformed TLP
- `UNCOR_COMPLETION_ABORT` - Completion abort

#### Uncorrectable Fatal Errors

```
(qemu) pcie_aer_inject_error -u -f id=cxl-type1-0,error=UNCOR_FLOW_CTRL
```

### 2. CXL-Specific Error Injection

#### Poison Injection

Inject poison into CXL memory to simulate memory corruption:

```
(qemu) cxl-inject-poison 0x0 0x40
# Inject poison at address 0x0, size 0x40 bytes
```

#### Uncorrectable Errors

```
(qemu) cxl-inject-uncorrectable-error
```

#### Correctable Errors

```
(qemu) cxl-inject-correctable-error
```

### 3. Link State Manipulation

Simulate link down/up events:

```
(qemu) set_link cxl-type1-0 off
# Link is now down

(qemu) set_link cxl-type1-0 on
# Link is back up
```

## Advanced Fault Injection

### Using QEMU's Error Injection Framework

QEMU has built-in error injection capabilities. To enable them, add to QEMU command line:

```bash
-device pcie-root-port,id=root_port13,chassis=0,slot=0,aer=on
```

The `aer=on` enables Advanced Error Reporting.

### Memory Backend Manipulation

You can manipulate the memory backend to simulate various failures:

```bash
# Remove memory backend (advanced)
(qemu) object_del cxl-mem1
# This will cause memory access failures
```

### Simulating Sudden Device Loss

For testing unexpected device removal:

```bash
# In host terminal
# Find QEMU process
ps aux | grep qemu

# Send device removal via QMP
echo '{"execute":"device_del", "arguments":{"id":"cxl-type1-0"}}' | \
  nc localhost 4444
```

## Testing Scenarios

### Scenario 1: Graceful Hot-Unplug

```bash
# 1. Inside VM - ensure no active I/O to CXL device
sync
echo 1 > /sys/bus/pci/devices/0000:0d:00.0/remove

# 2. In QEMU monitor
device_del cxl-type1-0

# 3. Verify in VM
lspci | grep CXL
# Should show device is gone
```

### Scenario 2: Sudden Device Loss

```bash
# 1. Inside VM - actively using CXL device
dd if=/dev/cxl-mem of=/dev/null bs=1M &

# 2. In QEMU monitor - immediately remove device
device_del cxl-type1-0

# 3. Check kernel logs
dmesg | tail -50
# Look for error handling
```

### Scenario 3: Error Injection During I/O

```bash
# 1. Inside VM - start I/O workload
fio --name=test --rw=randwrite --bs=4k --size=1G \
    --filename=/mnt/cxl_mount/testfile &

# 2. In QEMU monitor - inject errors
pcie_aer_inject_error -u id=cxl-type1-0,error=UNCOR_POISON_TLP

# 3. Monitor behavior
dmesg -w
```

### Scenario 4: Link Flapping

```bash
# Create a script to repeatedly toggle link state
for i in {1..10}; do
  echo "set_link cxl-type1-0 off" | nc localhost 1234
  sleep 2
  echo "set_link cxl-type1-0 on" | nc localhost 1234
  sleep 2
done
```

## Monitoring and Debugging

### Inside VM

```bash
# Watch PCI devices
watch -n 1 'lspci | grep CXL'

# Monitor kernel logs
dmesg -w | grep -i 'cxl\|pci\|aer'

# Check PCIe AER status
lspci -vvv -s 0d:00.0 | grep -A 20 'Advanced Error Reporting'

# Check CXL device status
ls -l /sys/bus/cxl/devices/
cat /sys/bus/cxl/devices/*/health_status
```

### In QEMU Monitor

```
# List all devices
info qtree

# Show PCI topology
info pci

# Show QOM tree
info qom-tree

# Check device status
device_list_properties cxl-type1
```

### Using QMP for Automated Testing

Create a Python script for automated testing:

```python
#!/usr/bin/env python3
import socket
import json
import time

def qmp_command(sock, cmd):
    sock.sendall(json.dumps(cmd).encode() + b'\n')
    response = sock.recv(4096)
    return json.loads(response)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 4444))

# Read banner
sock.recv(4096)

# Send capability negotiation
qmp_command(sock, {'execute': 'qmp_capabilities'})

# Hot-unplug device
qmp_command(sock, {
    'execute': 'device_del',
    'arguments': {'id': 'cxl-type1-0'}
})

time.sleep(5)

# Hot-plug device back
qmp_command(sock, {
    'execute': 'device_add',
    'arguments': {
        'driver': 'cxl-type1',
        'id': 'cxl-type1-0',
        'bus': 'root_port13',
        'memdev': 'cxl-mem1',
        'lsa': 'cxl-lsa1'
    }
})

sock.close()
```

## Expected Kernel Behavior

When a CXL device is hot-unplugged, the kernel should:

1. Detect device removal via PCIe hotplug event
2. Call device driver's `.remove()` callback
3. Flush any pending I/O operations
4. Unmap memory regions
5. Remove sysfs entries
6. Log the event in dmesg

### Check Driver Remove Path

```bash
# Inside VM
cat /proc/kallsyms | grep cxl | grep remove
```

## Troubleshooting

### Device Won't Unplug

```
# Check if device is in use
lsof | grep cxl

# Force removal (use with caution)
echo 1 > /sys/bus/pci/devices/0000:0d:00.0/remove
```

### QEMU Monitor Not Responding

```bash
# Check if monitor port is open
netstat -tuln | grep 1234

# Restart QEMU with monitor enabled
# Add to launch script: -monitor tcp:127.0.0.1:1234,server,nowait
```

### AER Injection Not Working

```bash
# Ensure AER is enabled in root port
# Modify launch script to add: aer=on to root port device

# Check kernel AER support
zcat /proc/config.gz | grep CONFIG_PCIEAER
```

## Integration with Existing Test Script

The `cxl_hotplug_test.sh` script provides all these capabilities in an easy-to-use interface:

```bash
# Test hot-unplug with automatic recovery
QEMU_MONITOR_PORT=1234 bash cxl_hotplug_test.sh auto

# Interactive testing
bash cxl_hotplug_test.sh
```

## References

- PCIe Base Specification (AER)
- CXL 3.0 Specification (Error Handling)
- QEMU Documentation: docs/pcie_aer.txt
- Linux Kernel: drivers/cxl/
