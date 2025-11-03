#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "hw/mem/pc-dimm.h"
#include "hw/virtio/virtio-crypto.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/pmem.h"
#include "qemu/range.h"
#include "qemu/rcu.h"
#include "sysemu/cryptodev.h"
#include "sysemu/hostmem.h"
#include "sysemu/numa.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_cache_coherency.h"
#include "hw/pci/msix.h"

#define DWORD_BYTE 4

/* Default CDAT entries for a type 1 device */
enum {
    CT1_CDAT_DSMAS,
    CT1_CDAT_DSLBIS0,
    CT1_CDAT_DSLBIS1,
    CT1_CDAT_DSLBIS2,
    CT1_CDAT_DSLBIS3,
    CT1_CDAT_DSEMTS,
    CT1_CDAT_NUM_ENTRIES
};

static CXLCacheRegion *host_memory_backend_get_cxl_cache(HostMemoryBackend *backend,
                                                          CXLType1Dev *ct1d)
{
    CXLCacheRegion *region;
    MemoryRegion *mr;

    if (!backend) {
        return NULL;
    }

    mr = host_memory_backend_get_memory(backend);
    if (!mr) {
        return NULL;
    }

    /* Allocate cache region if not already created */
    if (!ct1d->cache_regions) {
        region = g_new0(CXLCacheRegion, 1);
        region->size = int128_get64(backend->size);
        region->base = 0; /* Will be set by HDM decoder */
        region->cache = NULL; /* Will be allocated by coherency_init */
        ct1d->cache_regions = region;
    } else {
        region = ct1d->cache_regions;
    }

    return region;
}

static int ct1_build_cdat_entries_for_type1(CDATSubHeader **cdat_table,
                                         int dsmad_handle, CXLCacheRegion *mr)
{
    g_autofree CDATDsmas *dsmas = NULL;
    g_autofree CDATDslbis *dslbis0 = NULL;
    g_autofree CDATDslbis *dslbis1 = NULL;
    g_autofree CDATDslbis *dslbis2 = NULL;
    g_autofree CDATDslbis *dslbis3 = NULL;
    g_autofree CDATDsemts *dsemts = NULL;
    // Know from starting that how it takes

    dsmas = g_malloc(sizeof(*dsmas));
    if (!dsmas) {
        return -ENOMEM;
    }
    *dsmas = (CDATDsmas) {
        .header = {
            .type = CDAT_TYPE_DSMAS,
            .length = sizeof(*dsmas),
        },
        .DSMADhandle = dsmad_handle,
        .flags = CDAT_DSMAS_FLAG_NV,
        .DPA_base = 0,
        .DPA_length = int128_get64(mr->size),
    };

    /* For now, no memory side cache, plausiblish numbers */
    dslbis0 = g_malloc(sizeof(*dslbis0));
    if (!dslbis0) {
        return -ENOMEM;
    }
    *dslbis0 = (CDATDslbis) {
        .header = {
            .type = CDAT_TYPE_DSLBIS,
            .length = sizeof(*dslbis0),
        },
        .handle = dsmad_handle,
        .flags = HMAT_LB_MEM_MEMORY,
        .data_type = HMAT_LB_DATA_READ_LATENCY,
        .entry_base_unit = 10000, /* 10ns base */
        .entry[0] = 15, /* 150ns */
    };

    dslbis1 = g_malloc(sizeof(*dslbis1));
    if (!dslbis1) {
        return -ENOMEM;
    }
    *dslbis1 = (CDATDslbis) {
        .header = {
            .type = CDAT_TYPE_DSLBIS,
            .length = sizeof(*dslbis1),
        },
        .handle = dsmad_handle,
        .flags = HMAT_LB_MEM_MEMORY,
        .data_type = HMAT_LB_DATA_WRITE_LATENCY,
        .entry_base_unit = 10000,
        .entry[0] = 25, /* 250ns */
    };

    dslbis2 = g_malloc(sizeof(*dslbis2));
    if (!dslbis2) {
        return -ENOMEM;
    }
    *dslbis2 = (CDATDslbis) {
        .header = {
            .type = CDAT_TYPE_DSLBIS,
            .length = sizeof(*dslbis2),
        },
        .handle = dsmad_handle,
        .flags = HMAT_LB_MEM_MEMORY,
        .data_type = HMAT_LB_DATA_READ_BANDWIDTH,
        .entry_base_unit = 1000, /* GB/s */
        .entry[0] = 16,
    };

    dslbis3 = g_malloc(sizeof(*dslbis3));
    if (!dslbis3) {
        return -ENOMEM;
    }
    *dslbis3 = (CDATDslbis) {
        .header = {
            .type = CDAT_TYPE_DSLBIS,
            .length = sizeof(*dslbis3),
        },
        .handle = dsmad_handle,
        .flags = HMAT_LB_MEM_MEMORY,
        .data_type = HMAT_LB_DATA_WRITE_BANDWIDTH,
        .entry_base_unit = 1000, /* GB/s */
        .entry[0] = 16,
    };

    dsemts = g_malloc(sizeof(*dsemts));
    if (!dsemts) {
        return -ENOMEM;
    }
    *dsemts = (CDATDsemts) {
        .header = {
            .type = CDAT_TYPE_DSEMTS,
            .length = sizeof(*dsemts),
        },
        .DSMAS_handle = dsmad_handle,
        /* Reserved - the non volatile from DSMAS matters */
        .EFI_memory_type_attr = 2,
        .DPA_offset = 0,
        .DPA_length = int128_get64(mr->size),
    };

    /* Header always at start of structure */
    cdat_table[CT1_CDAT_DSMAS] = g_steal_pointer(&dsmas);
    cdat_table[CT1_CDAT_DSLBIS0] = g_steal_pointer(&dslbis0);
    cdat_table[CT1_CDAT_DSLBIS1] = g_steal_pointer(&dslbis1);
    cdat_table[CT1_CDAT_DSLBIS2] = g_steal_pointer(&dslbis2);
    cdat_table[CT1_CDAT_DSLBIS3] = g_steal_pointer(&dslbis3);
    cdat_table[CT1_CDAT_DSEMTS] = g_steal_pointer(&dsemts);

    return 0;
}

static int ct1_build_cdat_table(CDATSubHeader ***cdat_table, void *priv)
{
    g_autofree CDATSubHeader **table = NULL;
    CXLCacheRegion *cxlcacheregion;
    CXLType1Dev *ct1d = priv;
    int dsmad_handle = 0;
    int rc;


    cxlcacheregion = host_memory_backend_get_cxl_cache(ct1d->hostmem, ct1d);
    if (!cxlcacheregion) {
        return -EINVAL;
    }

    table = g_malloc0(CT1_CDAT_NUM_ENTRIES * sizeof(*table));
    if (!table) {
        return -ENOMEM;
    }

    rc = ct1_build_cdat_entries_for_type1(table, dsmad_handle++, cxlcacheregion);
    if (rc < 0) {
        return rc;
    }

    *cdat_table = g_steal_pointer(&table);

    return CT1_CDAT_NUM_ENTRIES;
}

static void ct1_free_cdat_table(CDATSubHeader **cdat_table, int num, void *priv)
{
    int i;

    for (i = 0; i < num; i++) {
        g_free(cdat_table[i]);
    }
    g_free(cdat_table);
}

static bool cxl_doe_cdat_rsp(DOECap *doe_cap)
{
    CDATObject *cdat = &CXL_TYPE1(doe_cap->pdev)->cxl_cstate.cdat;
    uint16_t ent;
    void *base;
    uint32_t len;
    CDATReq *req = pcie_doe_get_write_mbox_ptr(doe_cap);
    CDATRsp rsp;

    assert(cdat->entry_len);

    /* Discard if request length mismatched */
    if (pcie_doe_get_obj_len(req) <
        DIV_ROUND_UP(sizeof(CDATReq), DWORD_BYTE)) {
        return false;
    }

    ent = req->entry_handle;
    base = cdat->entry[ent].base;
    len = cdat->entry[ent].length;

    rsp = (CDATRsp) {
        .header = {
            .vendor_id = CXL_VENDOR_ID,
            .data_obj_type = CXL_DOE_TABLE_ACCESS,
            .reserved = 0x0,
            .length = DIV_ROUND_UP((sizeof(rsp) + len), DWORD_BYTE),
        },
        .rsp_code = CXL_DOE_TAB_RSP,
        .table_type = CXL_DOE_TAB_TYPE_CDAT,
        .entry_handle = (ent < cdat->entry_len - 1) ?
                        ent + 1 : CXL_DOE_TAB_ENT_MAX,
    };

    memcpy(doe_cap->read_mbox, &rsp, sizeof(rsp));
    memcpy(doe_cap->read_mbox + DIV_ROUND_UP(sizeof(rsp), DWORD_BYTE),
           base, len);

    doe_cap->read_mbox_len += rsp.header.length;

    return true;
}

static uint32_t ct1d_config_read(PCIDevice *pci_dev, uint32_t addr, int size)
{
    CXLType1Dev *ct1d = CXL_TYPE1(pci_dev);
    uint32_t val;

    if (pcie_doe_read_config(&ct1d->doe_cdat, addr, size, &val)) {
        return val;
    }

    return pci_default_read_config(pci_dev, addr, size);
}

static void ct1d_config_write(PCIDevice *pci_dev, uint32_t addr, uint32_t val,
                              int size)
{
    CXLType1Dev *ct1d = CXL_TYPE1(pci_dev);

    pcie_doe_write_config(&ct1d->doe_cdat, addr, val, size);
    pci_default_write_config(pci_dev, addr, val, size);
}

/*
 * Null value of all Fs suggested by IEEE RA guidelines for use of
 * EU, OUI and CID
 */
#define UI64_NULL ~(0ULL)

static void build_dvsecs(CXLType1Dev *ct1d)
{
    CXLComponentState *cxl_cstate = &ct1d->cxl_cstate;
    uint8_t *dvsec;

    dvsec = (uint8_t *)&(CXLDVSECDevice){
        .cap = 0x1e,
        .ctrl = 0x2,
        .status2 = 0x2,
        .range1_size_hi = ct1d->hostmem->size >> 32,
        .range1_size_lo = (2 << 5) | (2 << 2) | 0x3 |
        (ct1d->hostmem->size & 0xF0000000),
        .range1_base_hi = 0,
        .range1_base_lo = 0,
    };
    cxl_component_create_dvsec(cxl_cstate, CXL2_TYPE3_DEVICE,
                               PCIE_CXL_DEVICE_DVSEC_LENGTH,
                               PCIE_CXL_DEVICE_DVSEC,
                               PCIE_CXL2_DEVICE_DVSEC_REVID, dvsec);

    dvsec = (uint8_t *)&(CXLDVSECRegisterLocator){
        .rsvd         = 0,
        .reg0_base_lo = RBI_COMPONENT_REG | CXL_COMPONENT_REG_BAR_IDX,
        .reg0_base_hi = 0,
        .reg1_base_lo = RBI_CXL_DEVICE_REG | CXL_DEVICE_REG_BAR_IDX,
        .reg1_base_hi = 0,
    };
    cxl_component_create_dvsec(cxl_cstate, CXL2_TYPE3_DEVICE,
                               REG_LOC_DVSEC_LENGTH, REG_LOC_DVSEC,
                               REG_LOC_DVSEC_REVID, dvsec);
    dvsec = (uint8_t *)&(CXLDVSECDeviceGPF){
        .phase2_duration = 0x603, /* 3 seconds */
        .phase2_power = 0x33, /* 0x33 miliwatts */
    };
    cxl_component_create_dvsec(cxl_cstate, CXL2_TYPE3_DEVICE,
                               GPF_DEVICE_DVSEC_LENGTH, GPF_DEVICE_DVSEC,
                               GPF_DEVICE_DVSEC_REVID, dvsec);

    dvsec = (uint8_t *)&(CXLDVSECPortFlexBus){
        .cap                     = 0x26, /* 68B, IO, Mem, non-MLD */
        .ctrl                    = 0x02, /* IO always enabled */
        .status                  = 0x26, /* same as capabilities */
        .rcvd_mod_ts_data_phase1 = 0xef, /* WTF? */
    };
    cxl_component_create_dvsec(cxl_cstate, CXL2_TYPE3_DEVICE,
                               PCIE_FLEXBUS_PORT_DVSEC_LENGTH_2_0,
                               PCIE_FLEXBUS_PORT_DVSEC,
                               PCIE_FLEXBUS_PORT_DVSEC_REVID_2_0, dvsec);
}

static void hdm_decoder_commit(CXLType1Dev *ct1d, int which)
{
    ComponentRegisters *cregs = &ct1d->cxl_cstate.crb;
    uint32_t *cache_mem = cregs->cache_mem_registers;

    assert(which == 0);

    /* TODO: Sanity checks that the decoder is possible */
    ARRAY_FIELD_DP32(cache_mem, CXL_HDM_DECODER0_CTRL, COMMIT, 0);
    ARRAY_FIELD_DP32(cache_mem, CXL_HDM_DECODER0_CTRL, ERR, 0);

    ARRAY_FIELD_DP32(cache_mem, CXL_HDM_DECODER0_CTRL, COMMITTED, 1);
}

static void ct1d_reg_write(void *opaque, hwaddr offset, uint64_t value,
                           unsigned size)
{
    CXLComponentState *cxl_cstate = opaque;
    ComponentRegisters *cregs = &cxl_cstate->crb;
    CXLType1Dev *ct1d = container_of(cxl_cstate, CXLType1Dev, cxl_cstate);
    uint32_t *cache_mem = cregs->cache_mem_registers;
    bool should_commit = false;
    int which_hdm = -1;

    assert(size == 4);
    g_assert(offset < CXL2_COMPONENT_CM_REGION_SIZE);

    switch (offset) {
    case A_CXL_HDM_DECODER0_CTRL:
        should_commit = FIELD_EX32(value, CXL_HDM_DECODER0_CTRL, COMMIT);
        which_hdm = 0;
        break;
    default:
        break;
    }

    stl_le_p((uint8_t *)cache_mem + offset, value);
    if (should_commit) {
        hdm_decoder_commit(ct1d, which_hdm);
    }
}

static bool cxl_setup_memory(CXLType1Dev *ct1d, Error **errp)
{
    DeviceState *ds = DEVICE(ct1d);
    MemoryRegion *mr;
    char *name;

    if (!ct1d->hostmem) {
        error_setg(errp, "memdev property must be set");
        return false;
    }

    mr = host_memory_backend_get_memory(ct1d->hostmem);
    if (!mr) {
        error_setg(errp, "memdev property must be set");
        return false;
    }
    memory_region_set_nonvolatile(mr, true);
    memory_region_set_enabled(mr, true);
    host_memory_backend_set_mapped(ct1d->hostmem, true);

    if (ds->id) {
        name = g_strdup_printf("cxl-type3-dpa-space:%s", ds->id);
    } else {
        name = g_strdup("cxl-type3-dpa-space");
    }
    address_space_init(&ct1d->hostmem_as, mr, name);
    g_free(name);

    ct1d->cxl_dstate.pmem_size = ct1d->hostmem->size;

    if (!ct1d->lsa) {
        error_setg(errp, "lsa property must be set");
        return false;
    }

    return true;
}

static DOEProtocol doe_cdat_prot[] = {
    { CXL_VENDOR_ID, CXL_DOE_TABLE_ACCESS, cxl_doe_cdat_rsp },
    { }
};

static void ct1_realize(PCIDevice *pci_dev, Error **errp)
{
    CXLType1Dev *ct1d = CXL_TYPE1(pci_dev);
    CXLComponentState *cxl_cstate = &ct1d->cxl_cstate;
    ComponentRegisters *regs = &cxl_cstate->crb;
    MemoryRegion *mr = &regs->component_registers;
    uint8_t *pci_conf = pci_dev->config;
    unsigned short msix_num = 1;
    int i;

    if (!cxl_setup_memory(ct1d, errp)) {
        return;
    }

    pci_config_set_prog_interface(pci_conf, 0x10);
    pci_config_set_class(pci_conf, PCI_CLASS_MEMORY_CXL);

    pcie_endpoint_cap_init(pci_dev, 0x80);
    if (ct1d->sn != UI64_NULL) {
        pcie_dev_ser_num_init(pci_dev, 0x100, ct1d->sn);
        cxl_cstate->dvsec_offset = 0x100 + 0x0c;
    } else {
        cxl_cstate->dvsec_offset = 0x100;
    }

    ct1d->cxl_cstate.pdev = pci_dev;
    build_dvsecs(ct1d);

    regs->special_ops = g_new0(MemoryRegionOps, 1);
    regs->special_ops->write = ct1d_reg_write;

    cxl_component_register_block_init(OBJECT(pci_dev), cxl_cstate,
                                      TYPE_CXL_TYPE1);

    pci_register_bar(
        pci_dev, CXL_COMPONENT_REG_BAR_IDX,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64, mr);

    cxl_device_register_block_init(OBJECT(pci_dev), &ct1d->cxl_dstate);
    pci_register_bar(pci_dev, CXL_DEVICE_REG_BAR_IDX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_TYPE_64,
                     &ct1d->cxl_dstate.device_registers);

    /* MSI(-X) Initailization */
    msix_init_exclusive_bar(pci_dev, msix_num, 4, NULL);
    for (i = 0; i < msix_num; i++) {
        msix_vector_use(pci_dev, i);
    }

    /* DOE Initailization */
    pcie_doe_init(pci_dev, &ct1d->doe_cdat, 0x190, doe_cdat_prot, true, 0);

    cxl_cstate->cdat.build_cdat_table = ct1_build_cdat_table;
    cxl_cstate->cdat.free_cdat_table = ct1_free_cdat_table;
    cxl_cstate->cdat.private = ct1d;
    cxl_doe_cdat_init(cxl_cstate, errp);

    /* Initialize cache coherency tracking */
    if (ct1d->cache_regions) {
        MemoryRegion *hostmem_mr = host_memory_backend_get_memory(ct1d->hostmem);
        ct1d->coherency_state = cxl_cache_coherency_init(ct1d->cache_regions,
                                                          hostmem_mr);
        if (!ct1d->coherency_state) {
            error_setg(errp, "Failed to initialize cache coherency");
            return;
        }
    }
}

static void ct1_exit(PCIDevice *pci_dev)
{
    CXLType1Dev *ct1d = CXL_TYPE1(pci_dev);
    CXLComponentState *cxl_cstate = &ct1d->cxl_cstate;
    ComponentRegisters *regs = &cxl_cstate->crb;

    /* Mark device as offline and cleanup cache coherency */
    if (ct1d->coherency_state) {
        cxl_cache_device_offline(ct1d->coherency_state);
        cxl_cache_coherency_cleanup(ct1d->coherency_state);
        ct1d->coherency_state = NULL;
    }

    cxl_doe_cdat_release(cxl_cstate);
    g_free(regs->special_ops);

    if (ct1d->cache_regions) {
        if (ct1d->cache_regions->cache) {
            g_free(ct1d->cache_regions->cache);
        }
        g_free(ct1d->cache_regions);
        ct1d->cache_regions = NULL;
    }

    address_space_destroy(&ct1d->hostmem_as);
}

static void ct1d_reset(DeviceState *dev)
{
    CXLType1Dev *ct1d = CXL_TYPE1(dev);
    uint32_t *reg_state = ct1d->cxl_cstate.crb.cache_mem_registers;
    uint32_t *write_msk = ct1d->cxl_cstate.crb.cache_mem_regs_write_mask;

    cxl_component_register_init_common(reg_state, write_msk, CXL2_TYPE3_DEVICE);
    cxl_device_register_init_common(&ct1d->cxl_dstate);
}
// Create memory 
static Property ct1_props[] = {
    DEFINE_PROP_LINK("cryptodev", CXLType1Dev, vdev,
                     TYPE_VIRTIO_CRYPTO_CXL, VirtIOCryptoCXL *),
    DEFINE_PROP_LINK("memdev", CXLType1Dev, hostmem,
                     TYPE_MEMORY_BACKEND, HostMemoryBackend *),
    DEFINE_PROP_LINK("lsa", CXLType1Dev, lsa, TYPE_MEMORY_BACKEND,
                     HostMemoryBackend *),
    DEFINE_PROP_UINT64("sn", CXLType1Dev, sn, UI64_NULL),
    DEFINE_PROP_STRING("cdat", CXLType1Dev, cxl_cstate.cdat.filename),
    DEFINE_PROP_END_OF_LIST(),
};

static uint64_t get_lsa_size(CXLType1Dev *ct1d)
{
    MemoryRegion *mr;

    mr = host_memory_backend_get_memory(ct1d->lsa);
    return memory_region_size(mr);
}

static void validate_lsa_access(MemoryRegion *mr, uint64_t size,
                                uint64_t offset)
{
    assert(offset + size <= memory_region_size(mr));
    assert(offset + size > offset);
}

static uint64_t get_lsa(CXLType1Dev *ct1d, void *buf, uint64_t size,
                    uint64_t offset)
{
    MemoryRegion *mr;
    void *lsa;

    mr = host_memory_backend_get_memory(ct1d->lsa);
    validate_lsa_access(mr, size, offset);

    lsa = memory_region_get_ram_ptr(mr) + offset;
    memcpy(buf, lsa, size);

    return size;
}

static void set_lsa(CXLType1Dev *ct1d, const void *buf, uint64_t size,
                    uint64_t offset)
{
    MemoryRegion *mr;
    void *lsa;

    mr = host_memory_backend_get_memory(ct1d->lsa);
    validate_lsa_access(mr, size, offset);

    lsa = memory_region_get_ram_ptr(mr) + offset;
    memcpy(lsa, buf, size);
    memory_region_set_dirty(mr, offset, size);

    /// put the cxlcache into it.

    /*
     * Just like the PMEM, if the guest is not allowed to exit gracefully, label
     * updates will get lost.
     */
}

static void ct1_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);
    CXLType1Class *cvc = CXL_TYPE1_CLASS(oc);

    pc->realize = ct1_realize;
    pc->exit = ct1_exit;
    pc->class_id = PCI_CLASS_CRYPT_OTHER;
    pc->vendor_id = PCI_VENDOR_ID_INTEL;
    pc->device_id = 0xd93; /* LVF for now */
    pc->revision = 1;

    pc->config_write = ct1d_config_write;
    pc->config_read = ct1d_config_read;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->desc = "CXL.cache Device (Type 1)";
    dc->reset = ct1d_reset;
    device_class_set_props(dc, ct1_props);

    cvc->get_lsa_size = get_lsa_size;
    cvc->get_lsa = get_lsa;
    cvc->set_lsa = set_lsa;
}

static const TypeInfo ct1d_info = {
    .name = TYPE_CXL_TYPE1,
    .parent = TYPE_PCI_DEVICE,
    .class_size = sizeof(struct CXLType1Class),
    .class_init = ct1_class_init,
    .instance_size = sizeof(CXLType1Dev),
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CXL_DEVICE },
        { INTERFACE_PCIE_DEVICE },
        {}
    },
};

static void ct1d_registers(void)
{
    type_register_static(&ct1d_info);
}

type_init(ct1d_registers);
