/* SPDX-License-Identifier: MIT
 *
 * This file is derived from the rv32emu project (MIT licensed).
 * Ported/adapted for uemu — A RISC-V Virtual Platform Emulator.
 *
 * Copyright (c) 2020-2025 National Cheng Kung University, Taiwan
 * Copyright (c) 2025 Nuo Shen, Nanjing University
 *
 * See LICENSE-MIT for the full text of the MIT license.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/fs.h>

#include "core/riscv.h"
#include "device/plic.h"
#include "device/virtio.h"
#include "utils/logger.h"

#define DISK_BLK_SIZE 512

#define VBLK_FEATURES_0 0
#define VBLK_FEATURES_1 1 /* VIRTIO_F_VERSION_1 */
#define VBLK_QUEUE_NUM_MAX 1024
#define VBLK_QUEUE (vblk.queues[vblk.queue_sel])

#define VBLK_PRIV(x) ((struct virtio_blk_config *)x.priv)

PACKED(struct virtio_blk_config {
    uint64_t capacity;
    uint32_t size_max;
    uint32_t seg_max;

    struct virtio_blk_geometry {
        uint16_t cylinders;
        uint8_t heads;
        uint8_t sectors;
    } geometry;

    uint32_t blk_size;

    struct virtio_blk_topology {
        uint8_t physical_block_exp;
        uint8_t alignment_offset;
        uint16_t min_io_size;
        uint32_t opt_io_size;
    } topology;

    uint8_t writeback;
    uint8_t unused0[3];
    uint32_t max_discard_sectors;
    uint32_t max_discard_seg;
    uint32_t discard_sector_alignment;
    uint32_t max_write_zeroes_sectors;
    uint32_t max_write_zeroes_seg;
    uint8_t write_zeroes_may_unmap;
    uint8_t unused1[3];
    uint64_t disk_size;
});

PACKED(struct vblk_req_header {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
    uint8_t status;
});

/* Set in main.c */
char *disk_file = NULL;

static virtio_blk_state_t vblk;

static inline void vblk_set_fail() {
    vblk.status |= VIRTIO_STATUS_DEVICE_NEEDS_RESET;
    if (vblk.status & VIRTIO_STATUS_DRIVER_OK)
        vblk.interrupt_status |= VIRTIO_INT_CONF_CHANGE;
}

static inline uint32_t vblk_preprocess(uint32_t addr) {
    if (addr >= MSIZE || (addr & 0b11)) {
        vblk_set_fail();
        return 0;
    }
    return addr >> 2;
}

static inline void vblk_update_status(uint32_t status) {
    vblk.status |= status;
    if (status)
        return;

    /* Reset */
    uint32_t device_features = vblk.device_features;
    uint32_t *ram = vblk.ram;
    uint32_t *disk = vblk.disk;
    uint64_t disk_size = vblk.disk_size;
    int disk_fd = vblk.disk_fd;
    void *priv = vblk.priv;
    uint32_t capacity = VBLK_PRIV(vblk)->capacity;
    memset(&vblk, 0, sizeof(vblk));
    vblk.device_features = device_features;
    vblk.ram = ram;
    vblk.disk = disk;
    vblk.disk_size = disk_size;
    vblk.disk_fd = disk_fd;
    vblk.priv = priv;
    VBLK_PRIV(vblk)->capacity = capacity;
}

static inline void vblk_write_handler(uint64_t sector, uint64_t desc_addr,
                                      uint32_t len) {
    void *dest = (void *)((uintptr_t)vblk.disk + sector * DISK_BLK_SIZE);
    const void *src = (void *)((uintptr_t)vblk.ram + desc_addr);
    memcpy(dest, src, len);
}

static inline void vblk_read_handler(uint64_t sector, uint64_t desc_addr,
                                     uint32_t len) {
    void *dest = (void *)((uintptr_t)vblk.ram + desc_addr);
    const void *src = (void *)((uintptr_t)vblk.disk + sector * DISK_BLK_SIZE);
    memcpy(dest, src, len);
}

static inline int vblk_desc_handler(const virtio_blk_queue_t *queue,
                                    uint16_t desc_idx, uint32_t *plen) {
    /* A full virtio_blk_req is represented by 3 descriptors, where
     * the first descriptor contains:
     *   le32 type
     *   le32 reserved
     *   le64 sector
     * the second descriptor contains:
     *   u8 data[][512]
     * the third descriptor contains:
     *   u8 status
     */
    struct virtq_desc vq_desc[3];

    /* Collect the descriptors */
    for (int i = 0; i < 3; i++) {
        /* The size of the `struct virtq_desc` is 4 words */
        const struct virtq_desc *desc =
            (struct virtq_desc *)&vblk.ram[queue->queue_desc + desc_idx * 4];

        /* Retrieve the fields of current descriptor */
        vq_desc[i].addr = desc->addr;
        vq_desc[i].len = desc->len;
        vq_desc[i].flags = desc->flags;
        desc_idx = desc->next;
    }

    /* The next flag for the first and second descriptors should be set,
     * whereas for the third descriptor is should not be set
     */
    if (!(vq_desc[0].flags & VIRTIO_DESC_F_NEXT) ||
        !(vq_desc[1].flags & VIRTIO_DESC_F_NEXT) ||
        (vq_desc[2].flags & VIRTIO_DESC_F_NEXT)) {
        /* since the descriptor list is abnormal, we don't write the status
         * back here */
        vblk_set_fail();
        return -1;
    }

    /* Process the header */
    const struct vblk_req_header *header =
        (struct vblk_req_header *)((uintptr_t)vblk.ram + vq_desc[0].addr);
    uint32_t type = header->type;
    uint64_t sector = header->sector;
    uint8_t *status = (uint8_t *)((uintptr_t)vblk.ram + vq_desc[2].addr);

    /* Check sector index is valid */
    if (sector > (VBLK_PRIV(vblk)->capacity - 1)) {
        *status = VIRTIO_BLK_S_IOERR;
        return -1;
    }

    /* Process the data */
    switch (type) {
        case VIRTIO_BLK_T_IN:
            vblk_read_handler(sector, vq_desc[1].addr, vq_desc[1].len);
            break;
        case VIRTIO_BLK_T_OUT:
            if (vblk.device_features & VIRTIO_BLK_F_RO) { /* readonly */
                // log_error("Fail to write on a read only block device");
                *status = VIRTIO_BLK_S_IOERR;
                return -1;
            }
            vblk_write_handler(sector, vq_desc[1].addr, vq_desc[1].len);
            break;
        default:
            // log_error("Unsupported virtio-blk operation");
            *status = VIRTIO_BLK_S_UNSUPP;
            return -1;
    }

    /* Return the device status */
    *status = VIRTIO_BLK_S_OK;
    *plen = vq_desc[1].len;

    return 0;
}

static inline void virtio_queue_notify_handler(int index) {
    uint32_t *ram = vblk.ram;
    virtio_blk_queue_t *queue = &vblk.queues[index];
    if (vblk.status & VIRTIO_STATUS_DEVICE_NEEDS_RESET)
        return;

    if (!((vblk.status & VIRTIO_STATUS_DRIVER_OK) && queue->ready))
        return vblk_set_fail();

    /* Check for new buffers */
    uint16_t new_avail = ram[queue->queue_avail] >> 16;
    if (new_avail - queue->last_avail > (uint16_t)queue->queue_num)
        return vblk_set_fail();

    if (queue->last_avail == new_avail)
        return;

    /* Process them */
    uint16_t new_used =
        ram[queue->queue_used] >> 16; /* virtq_used.idx (le16) */
    while (queue->last_avail != new_avail) {
        /* Obtain the index in the ring buffer */
        uint16_t queue_idx = queue->last_avail % queue->queue_num;

        /* Since each buffer index occupies 2 bytes but the memory is aligned
         * with 4 bytes, and the first element of the available queue is stored
         * at ram[queue->queue_avail + 1], to acquire the buffer index, it
         * requires the following array index calculation and bit shifting.
         * Check also the `struct virtq_avail` on the spec.
         */
        uint16_t buffer_idx = ram[queue->queue_avail + 1 + queue_idx / 2] >>
                              (16 * (queue_idx % 2));

        /* Consume request from the available queue and process the data in the
         * descriptor list.
         */
        uint32_t len = 0;
        int result = vblk_desc_handler(queue, buffer_idx, &len);
        if (result != 0)
            return vblk_set_fail();

        /* Write used element information (`struct virtq_used_elem`) to the used
         * queue */
        uint32_t vq_used_addr =
            queue->queue_used + 1 + (new_used % queue->queue_num) * 2;
        ram[vq_used_addr] = buffer_idx; /* virtq_used_elem.id  (le32) */
        ram[vq_used_addr + 1] = len;    /* virtq_used_elem.len (le32) */
        queue->last_avail++;
        new_used++;
    }

    /* Check le32 len field of `struct virtq_used_elem` on the spec  */
    vblk.ram[queue->queue_used] &= 0xffff; /* Reset low 16 bits to zero */
    vblk.ram[queue->queue_used] |= ((uint32_t)new_used) << 16; /* len */

    /* Send interrupt, unless VIRTQ_AVAIL_F_NO_INTERRUPT is set */
    if (!(ram[queue->queue_avail] & 1))
        vblk.interrupt_status |= VIRTIO_INT_USED_RING;
}

static inline void vblk_update_irq() {
    if (vblk.interrupt_status)
        plic_set_irq(VIRTIO_BLK_IRQ, 1);
    else
        plic_set_irq(VIRTIO_BLK_IRQ, 0);
}

static uint64_t vblk_read(uint64_t addr, size_t n) {
    uint64_t offset = addr - VIRTIO_BLK_BASE, r = 0;
    switch (offset >> 2) {
        case VIRTIO_MagicValue: r = VIRTIO_MAGIC_NUMBER; break;
        case VIRTIO_Version: r = VIRTIO_VERSION; break;
        case VIRTIO_DeviceID: r = VIRTIO_BLK_DEV_ID; break;
        case VIRTIO_VendorID: r = VIRTIO_VENDOR_ID; break;
        case VIRTIO_DeviceFeatures:
            r = vblk.device_features_sel == 0
                    ? VBLK_FEATURES_0 | vblk.device_features
                    : (vblk.device_features_sel == 1 ? VBLK_FEATURES_1 : 0);
            break;
        case VIRTIO_QueueNumMax: r = VBLK_QUEUE_NUM_MAX; break;
        case VIRTIO_QueueReady: r = (uint32_t)VBLK_QUEUE.ready; break;
        case VIRTIO_InterruptStatus: r = vblk.interrupt_status; break;
        case VIRTIO_Status: r = vblk.status; break;
        case VIRTIO_ConfigGeneration: r = VIRTIO_CONFIG_GENERATE; break;
        default:
            /* Read configuration from the corresponding register */
            r = ((uint32_t *)VBLK_PRIV(vblk))[(offset >> 2) - VIRTIO_Config];
            break;
    }
    vblk_update_irq();
    return r;
}

static void vblk_write(uint64_t addr, uint64_t value, size_t n) {
    uint64_t offset = addr - VIRTIO_BLK_BASE;
    switch (offset >> 2) {
        case VIRTIO_DeviceFeaturesSel: vblk.device_features_sel = value; break;
        case VIRTIO_DriverFeatures:
            vblk.driver_features_sel == 0 ? (vblk.driver_features = value) : 0;
            break;
        case VIRTIO_DriverFeaturesSel: vblk.driver_features_sel = value; break;
        case VIRTIO_QueueSel:
            if (value < ARRAY_SIZE(vblk.queues))
                vblk.queue_sel = value;
            else
                vblk_set_fail();
            break;
        case VIRTIO_QueueNum:
            if (value > 0 && value <= VBLK_QUEUE_NUM_MAX)
                VBLK_QUEUE.queue_num = value;
            else
                vblk_set_fail();
            break;
        case VIRTIO_QueueReady:
            VBLK_QUEUE.ready = value & 1;
            if (value & 1)
                VBLK_QUEUE.last_avail = vblk.ram[VBLK_QUEUE.queue_avail] >> 16;
            break;
        case VIRTIO_QueueDescLow:
            VBLK_QUEUE.queue_desc = vblk_preprocess(value);
            break;
        case VIRTIO_QueueDescHigh:
            if (value)
                vblk_set_fail();
            break;
        case VIRTIO_QueueDriverLow:
            VBLK_QUEUE.queue_avail = vblk_preprocess(value);
            break;
        case VIRTIO_QueueDriverHigh:
            if (value)
                vblk_set_fail();
            break;
        case VIRTIO_QueueDeviceLow:
            VBLK_QUEUE.queue_used = vblk_preprocess(value);
            break;
        case VIRTIO_QueueDeviceHigh:
            if (value)
                vblk_set_fail();
            break;
        case VIRTIO_QueueNotify:
            if (value < ARRAY_SIZE(vblk.queues))
                virtio_queue_notify_handler(value);
            else
                vblk_set_fail();
            break;
        case VIRTIO_InterruptACK: vblk.interrupt_status &= ~value; break;
        case VIRTIO_Status: vblk_update_status(value); break;
        default:
            /* Write configuration to the corresponding register */
            ((uint32_t *)VBLK_PRIV(vblk))[(offset >> 2) - VIRTIO_Config] =
                value;
            break;
    }
    vblk_update_irq();
}

void vblk_init() {
    memset(&vblk, 0, sizeof(vblk));
    vblk.disk_fd = -1;
    vblk.ram = (uint32_t *)rv.memory;

    /* Allocate memory for the private member */
    vblk.priv = calloc(1, sizeof(struct virtio_blk_config));
    assert(vblk.priv);

    /* No disk image is provided */
    if (!disk_file || *disk_file == '\0') {
        /* By setting the block capacity to zero, the kernel will
         * then not to touch the device after booting */
        VBLK_PRIV(vblk)->capacity = 0;
        goto register_device;
    }

    /* Open disk file */
    int disk_fd = open(disk_file, O_RDWR);
    if (disk_fd < 0) {
        log_error("Could not open %s: %s", disk_file, strerror(errno));
        goto fail;
    }

    struct stat st;
    if (fstat(disk_fd, &st) == -1) {
        log_error("fstat failed: %s", strerror(errno));
        goto disk_size_fail;
    }

    const char *disk_file_dirname = dirname(disk_file);
    if (!disk_file_dirname) {
        log_error("Fail dirname disk_file: %s: %s", disk_file, strerror(errno));
        goto disk_size_fail;
    }

    /* Get the disk size */
    uint64_t disk_size;
    if (!strcmp(disk_file_dirname, "/dev")) { /* from /dev/, leverage ioctl */
        if ((st.st_mode & S_IFMT) != S_IFBLK) {
            log_error("%s is not block device", disk_file);
            goto fail;
        }
        if (ioctl(disk_fd, BLKGETSIZE64, &disk_size) == -1) {
            log_error("BLKGETSIZE64 failed: %s", strerror(errno));
            goto disk_size_fail;
        }
    } else {
        disk_size = st.st_size;
    }
    VBLK_PRIV(vblk)->disk_size = disk_size;

    /* Set up the disk memory */
    uint32_t *disk_mem = mmap(NULL, VBLK_PRIV(vblk)->disk_size,
                              PROT_READ | PROT_WRITE, MAP_SHARED, disk_fd, 0);
    if (disk_mem == MAP_FAILED)
        goto disk_mem_err;
    close(disk_fd);

    assert(!(((uintptr_t)disk_mem) & 0b11));

    vblk.disk = disk_mem;
    VBLK_PRIV(vblk)->capacity =
        (VBLK_PRIV(vblk)->disk_size - 1) / DISK_BLK_SIZE + 1;

register_device:
    rv_add_device((device_t){
        .name = "virtio-blk",
        .start = VIRTIO_BLK_BASE,
        .end = VIRTIO_BLK_BASE + VIRTIO_BLK_SIZE - 1,
        .read = vblk_read,
        .write = vblk_write,
    });

    return;

disk_mem_err:
    log_error("Could not map disk %s: %s", disk_file, strerror(errno));

disk_size_fail:
    close(disk_fd);

fail:
    exit(EXIT_FAILURE);
}

void vblk_destroy() {
    disk_file = NULL;
    munmap(vblk.disk, VBLK_PRIV(vblk)->disk_size);
    free(vblk.priv);
}
