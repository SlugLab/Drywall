# CXL Type 1 Device Cache Coherency Implementation

## Overview

This implementation provides page-level write protection for tracking cache coherency for CXL Type 1 devices (e.g., crypto accelerators) without relying on Intel-specific features like Sub-Page Protection (SPP). The design follows the proposal in the CSE290X Final Report: "Drywall: Reinforce the CXL malicious state from kernel and TDX applications".

## Architecture

### Key Components

1. **Cache Coherency State Tracking** (`hw/cxl/cxl-cache-coherency.c`)
   - Tracks page-level write protection for cachelines
   - Maintains MESI (Modified, Exclusive, Shared, Invalid) state for each cacheline
   - Implements ATS (Address Translation Services) bit tracking for exclusive access
   - Provides backup/restore mechanism for device hot-plug/unplug scenarios

2. **CXL Cache Region** (`include/hw/cxl/cxl.h`)
   - Defines `CXLCache` structure with:
     - 64-byte cacheline data
     - MESI state
     - ATS flags for exclusive access tracking
     - Device-to-Host request queue
   - Defines `CXLCacheRegion` structure for managing multiple cachelines

3. **CXL Type 1 Device Integration** (`hw/pci/cxl-type1.c`)
   - Integrates cache coherency tracking into CXL Type 1 device lifecycle
   - Initializes coherency state on device realize
   - Cleans up and restores cachelines on device exit

## Key Features

### 1. Page-Level Write Protection

Instead of using Intel SPP (which requires specific CPU support), we implement write protection at the page level:

```c
typedef struct CXLCachePage {
    hwaddr page_addr;              /* Page-aligned address */
    MemoryRegion *page_mr;         /* Memory region for this page */
    bool write_protected;          /* Is page write-protected? */
    uint64_t cacheline_bitmap;     /* Bitmap of tracked cachelines (64 lines/page) */
    uint8_t backup_data[PAGE_SIZE]; /* Backup for exclusive cachelines */
} CXLCachePage;
```

This approach:
- Works on any architecture, not just Intel
- Uses QEMU's memory region operations to intercept writes
- Tracks individual cachelines within a 4KB page using a bitmap
- Maintains backups for recovery on device failure

### 2. MESI State Management

Each cacheline can be in one of four states:
- **M (Modified)**: Cacheline is dirty and exclusive to the device
- **E (Exclusive)**: Cacheline is clean and exclusive to the device
- **S (Shared)**: Cacheline is shared between device and host
- **I (Invalid)**: Cacheline is not cached by the device

State transitions are managed automatically:
- `cxl_cache_mark_exclusive()`: I → E
- Device write: E → M
- `cxl_cache_release_exclusive()`: M/E → I (with write-back if modified)

### 3. ATS Bit Tracking

The Address Translation Services (ATS) flags track whether a device can take exclusive access to a cacheline:

```c
void cxl_cache_mark_exclusive(CXLCacheCoherencyState *state, hwaddr addr,
                               uint32_t ats_flags)
{
    cache->ats = ats_flags | 0x1; /* Set exclusive bit */
    cache->state = E; /* Exclusive state */
    /* Backup current data for recovery */
    memcpy(&page->backup_data[cl_offset], src, CACHELINE_SIZE);
}
```

### 4. Device Hot-Plug/Unplug Handling

When a device goes offline (hot-unplug or failure):

```c
void cxl_cache_device_offline(CXLCacheCoherencyState *state)
{
    /* Restore all exclusive cachelines from backup */
    for each tracked cacheline {
        if (exclusive) {
            memcpy(dst, backup_data, CACHELINE_SIZE);
            cache->state = I;
        }
    }
}
```

This ensures:
- No data loss when device fails
- System can continue with software fallback (e.g., software crypto)
- Kernel doesn't panic from lost cacheline state

## Usage Example

### For a Crypto Accelerator

1. **Mark cachelines as exclusive-able** before crypto operation:
```c
hwaddr crypto_buffer_addr = ...;
cxl_cache_mark_exclusive(ct1d->coherency_state, crypto_buffer_addr,
                          ATS_FLAG_CRYPTO);
```

2. **Device performs crypto operation** on exclusive cacheline

3. **Release cacheline** after operation:
```c
cxl_cache_release_exclusive(ct1d->coherency_state, crypto_buffer_addr);
```

4. **On device failure**, the system automatically:
   - Detects offline state
   - Restores cacheline from backup
   - Falls back to software crypto implementation

## Threat Model Mitigation

This implementation addresses the threats outlined in the proposal:

### Threat 1: Lower ability due to device hot-plug or malfunction
- **Mitigation**: Backup mechanism allows recovery without data loss
- **Result**: System continues with software fallback

### Threat 2: Security vulnerabilities from exclusive cacheline access
- **Mitigation**: ATS bit tracking ensures controlled exclusive access
- **Result**: Malicious device cannot leak sensitive data through cacheline state

### Threat 3: Memory access latency for multi-processor systems
- **Mitigation**: Page-level tracking minimizes overhead
- **Result**: Only actively used cachelines incur tracking cost

## Integration with LUKS

For the LUKS encryption use case mentioned in the proposal:

```
┌─────────────────────────┐
│  LUKS dm-crypt Layer    │
│  (Linux Kernel)         │
└──────────┬──────────────┘
           │
           │ Crypto requests
           ▼
┌─────────────────────────┐
│ CXL Type 1 Crypto       │
│ Accelerator (Hardware)  │
│                         │
│ - Cache coherency       │
│ - ATS tracking          │
│ - Backup/restore        │
└─────────────────────────┘
```

Benefits:
- Faster encryption/decryption through hardware offload
- Safe fallback to software crypto on device failure
- No data corruption from lost cacheline state

## Future Work

1. **eBPF Co-processor Integration**: Add eBPF processor near CXL devices for filtering requests
2. **TDX Integration**: Extend to support verified database in TDX enclaves
3. **Performance Optimization**: Fine-tune page protection granularity
4. **Multi-device Support**: Handle multiple CXL Type 1 devices sharing cachelines

## Testing

To test this implementation:

1. Build QEMU with CXL support:
```bash
./configure --target-list=x86_64-softmmu --disable-werror --disable-cocoa
ninja
```

2. Run QEMU with CXL Type 1 device:
```bash
qemu-system-x86_64 \
  -M q35,cxl=on \
  -device cxl-type1,id=crypto0,memdev=mem0,cryptodev=crypto0 \
  -object memory-backend-ram,id=mem0,size=256M \
  ...
```

3. Test device hot-plug/unplug:
```bash
# In QEMU monitor
device_del crypto0
# Verify system continues operation with software crypto
```

## References

- CXL 3.0 Specification
- "Drywall: Reinforce the CXL malicious state from kernel and TDX applications" - CSE290X Final Report
- QEMU CXL Device Implementation
