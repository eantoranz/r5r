/*
 * A sample, extra-simple block driver. Updated for kernel 2.6.31.
 *
 * (C) 2003 Eklektix, Inc.
 * (C) 2010 Pat Patterson <pat at superpat dot com>
 * Redistributable under the terms of the GNU GPL.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h> /* printk() */
#include <linux/fs.h>     /* everything... */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>

MODULE_LICENSE("Dual BSD/GPL");
static char *Version = "1.4";

static int major_num = 0;
module_param(major_num, int, 0);
static int logical_block_size = 512;
module_param(logical_block_size, int, 0);
static int nsectors = 1024; /* How big the drive is */
module_param(nsectors, int, 0);

/*
 * We can tweak our hardware sector size, but the kernel talks to us
 * in terms of small sectors, always.
 */
#define KERNEL_SECTOR_SIZE 512

/*
 * Our request queue.
 */
static struct request_queue *Queue;

/*
 * The internal representation of our device.
 */
static struct r5r_device {
	unsigned long size;
	spinlock_t lock;
	u8 *data;
	struct gendisk *gd;
} Device;

/*
 * Handle an I/O request.
 */
static void r5r_transfer(struct r5r_device *dev, sector_t sector,
		unsigned long nsect, char *buffer, int write) {
	unsigned long offset = sector * logical_block_size;
	unsigned long nbytes = nsect * logical_block_size;

	if ((offset + nbytes) > dev->size) {
		printk (KERN_NOTICE "r5r: Beyond-end write (%ld %ld)\n", offset, nbytes);
		return;
	}
	if (write)
		memcpy(dev->data + offset, buffer, nbytes);
	else
		memcpy(buffer, dev->data + offset, nbytes);
}

static void r5r_request(struct request_queue *q) {
	struct request *req;

	req = blk_fetch_request(q);
	while (req != NULL) {
		if (req->cmd_type != REQ_TYPE_FS) {
			printk (KERN_NOTICE "r5r: Skip non-CMD request\n");
			__blk_end_request_all(req, -EIO);
			continue;
		}
		r5r_transfer(&Device, blk_rq_pos(req), blk_rq_cur_sectors(req),
				req->buffer, rq_data_dir(req));
		if ( ! __blk_end_request_cur(req, 0) ) {
			req = blk_fetch_request(q);
		}
	}
}

/*
 * The HDIO_GETGEO ioctl is handled in blkdev_ioctl(), which
 * calls this. We need to implement getgeo, since we can't
 * use tools such as fdisk to partition the drive otherwise.
 */
int r5r_getgeo(struct block_device * block_device, struct hd_geometry * geo) {
	long size;

	/* We have no real geometry, of course, so make something up. */
	size = Device.size * (logical_block_size / KERNEL_SECTOR_SIZE);
	geo->cylinders = (size & ~0x3f) >> 6;
	geo->heads = 4;
	geo->sectors = 16;
	geo->start = 0;
	return 0;
}

/*
 * The device operations structure.
 */
static struct block_device_operations r5r_ops = {
		.owner  = THIS_MODULE,
		.getgeo = r5r_getgeo
};

static int __init r5r_init(void) {
	/*
	 * Set up our internal device.
	 */
	Device.size = nsectors * logical_block_size;
	spin_lock_init(&Device.lock);
	Device.data = vmalloc(Device.size);
	if (Device.data == NULL)
		return -ENOMEM;
	/*
	 * Get a request queue.
	 */
	Queue = blk_init_queue(r5r_request, &Device.lock);
	if (Queue == NULL)
		goto out;
	blk_queue_logical_block_size(Queue, logical_block_size);
	/*
	 * Get registered.
	 */
	major_num = register_blkdev(major_num, "r5r");
	if (major_num < 0) {
		printk(KERN_WARNING "r5r: unable to get major number\n");
		goto out;
	}
	/*
	 * And the gendisk structure.
	 */
	Device.gd = alloc_disk(16);
	if (!Device.gd)
		goto out_unregister;
	Device.gd->major = major_num;
	Device.gd->first_minor = 0;
	Device.gd->fops = &r5r_ops;
	Device.gd->private_data = &Device;
	strcpy(Device.gd->disk_name, "r5r0");
	set_capacity(Device.gd, nsectors);
	Device.gd->queue = Queue;
	add_disk(Device.gd);

        mm_segment_t oldfs = get_fs();
        set_fs(KERNEL_DS);

	struct file * theFile = filp_open("/home/debian/r5r.txt", O_RDONLY | O_LARGEFILE, 0);
	if (!IS_ERR(theFile)) {
		printk(KERN_INFO "File opened without problems\n");
		int fileSize = i_size_read(theFile->f_dentry->d_inode);
		printk(KERN_INFO "Size: %d bytes\n", fileSize);
		char content[fileSize];
		loff_t offset;
		offset = 0;
		int ret;
		ret = vfs_read(theFile, content, fileSize, &offset);
		printk(KERN_INFO "r5r, ret: %d offset %d\n", ret, offset);
		if (ret >= 0) {
			int i;
			for (i = 0; i < fileSize; i++) {
				printk(KERN_INFO "%d (%c)\n", content[i], content[i]);
			}
		}
		filp_close(theFile, NULL);
	} else {
		printk(KERN_INFO "Couldn't open file\n");
	}

	set_fs(oldfs);

	return 0;

out_unregister:
	unregister_blkdev(major_num, "r5r");
out:
	vfree(Device.data);
	return -ENOMEM;
}

static void __exit r5r_exit(void)
{
	del_gendisk(Device.gd);
	put_disk(Device.gd);
	unregister_blkdev(major_num, "r5r");
	blk_cleanup_queue(Queue);
	vfree(Device.data);
}

module_init(r5r_init);
module_exit(r5r_exit);
