/*
 * Virtio crypto device
 *
 * Copyright (c) 2016 HUAWEI TECHNOLOGIES CO., LTD.
 *
 * Authors:
 *    Gonglei <arei.gonglei@huawei.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.  See the COPYING file in the
 * top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-pci.h"
#include "hw/virtio/virtio-crypto.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qemu/typedefs.h"
#include "qom/object.h"

typedef struct VirtIOCryptoCXL VirtIOCryptoCXL;
// Todo CXL Type 1 wrapper ATS wrapper
/*
 * virtio-crypto-pci: This extends VirtioPCIProxy.
 */
#define TYPE_VIRTIO_CRYPTO_CXL "virtio-crypto-cxl"
DECLARE_INSTANCE_CHECKER(VirtIOCryptoCXL, VIRTIO_CRYPTO_PCI,
                         TYPE_VIRTIO_CRYPTO_CXL)
                         
struct VirtIOCryptoCXL {
    VirtIOPCIProxy parent_obj;
    VirtIOCrypto vdev;
    CXLCacheRegion* ctype1;
};

static Property virtio_crypto_cxl_properties[] = {
    // Two ioevent for queuing
    DEFINE_PROP_BIT("ioeventfd", VirtIOPCIProxy, flags,
                    VIRTIO_PCI_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_UINT32("vectors", VirtIOPCIProxy, nvectors, 2),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_crypto_cxl_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VirtIOCryptoCXL *vcrypto = VIRTIO_CRYPTO_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&vcrypto->vdev);

    if (vcrypto->vdev.conf.cryptodev == NULL) {
        error_setg(errp, "'cryptodev' parameter expects a valid object");
        return;
    }

    virtio_pci_force_virtio_1(vpci_dev);
    if (!qdev_realize(vdev, BUS(&vpci_dev->bus), errp)) {
        return;
    }
}

static void virtio_crypto_cxl_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);

    k->realize = virtio_crypto_cxl_realize;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_props(dc, virtio_crypto_cxl_properties);
    pcidev_k->class_id = PCI_CLASS_OTHERS;
    
}

static void virtio_crypto_initfn(Object *obj)
{
    VirtIOCryptoCXL *dev = VIRTIO_CRYPTO_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_CRYPTO);
}

static const VirtioPCIDeviceTypeInfo virtio_crypto_cxl_info = {
    .generic_name  = TYPE_VIRTIO_CRYPTO_CXL,
    .instance_size = sizeof(VirtIOCryptoCXL), // todo
    .instance_init = virtio_crypto_initfn,
    .class_init    = virtio_crypto_cxl_class_init,
};

static void virtio_crypto_cxl_register_types(void)
{
    virtio_pci_types_register(&virtio_crypto_cxl_info);
}
type_init(virtio_crypto_cxl_register_types)
