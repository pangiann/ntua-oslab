/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * Christopni (aka Christopoulos Nikos), 
 * PanGiann (aka Giannoulis Panagiotis)
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/page-flags.h>
#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"




/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;

	WARN_ON ( !(sensor = state->sensor));
	/* ? */
	return state->buf_timestamp != sensor->msr_data[BATT]->last_update;
	/* The following return is bogus, just for the stub to compile */
	 /* ? */
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;

	debug("leaving\n");
	int ret;
	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	 WARN_ON( !(sensor = state->sensor));


	/* ? */
	/* Why use spinlocks? See LDD3, p. 119 */

	/*
	 * Any new data available?
	 */


	 spin_lock_irq(&sensor->lock);
	 uint32_t timestamp = sensor->msr_data[BATT]->last_update;
	 uint32_t new_value = sensor->msr_data[state->type]->values[0];
	 spin_unlock_irq(&sensor->lock);

	/* ? */

	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */


	/* ? */
	long value;
	if (lunix_chrdev_state_needs_refresh(state)) {
		state->buf_timestamp = timestamp;
		if (!state->raw_data) {
				switch (state->type) {
						case BATT:
								value = lookup_voltage[new_value];
								break;
						case TEMP:
								value = lookup_temperature[new_value];
								break;
						case LIGHT:
								value = lookup_light[new_value];
								break;
						default:
								debug("We shouldn't be here\n");
								return -EAGAIN;

				}


				debug("new data are %ld\n", value);
				state->buf_lim = snprintf(state->buf_data, LUNIX_CHRDEV_BUFSZ, "%ld.%ld\n", value/1000, value%1000);
				debug("New data came and specifically %d bytes\n", state->buf_lim);
		}
		else {
				debug("New data without formatting them\n");
				state->buf_lim = snprintf(state->buf_data, LUNIX_CHRDEV_BUFSZ, "%ld\n", new_value);
		}
	}
	else {
		debug("No new data\n");
		return -EAGAIN;
	}

out:
	debug("leaving\n");
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	/* ? */
	struct lunix_chrdev_state_struct *lunix_chrdev_state;
	int ret;

	debug("entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */


	/* Allocate a new Lunix character device private state structure */

	lunix_chrdev_state = kzalloc(sizeof(*lunix_chrdev_state), GFP_KERNEL);
	if (!lunix_chrdev_state) {
		ret = -ENOMEM;
		printk(KERN_ERR "Failed to allocate memory for Lunix driver state");
		goto out;
	}
	int minor_num = iminor(inode);
	int lunix_sensor_num = minor_num >> 3;
	lunix_chrdev_state->sensor = &(lunix_sensors[lunix_sensor_num]);
  sema_init(&lunix_chrdev_state->lock, 1);
	lunix_chrdev_state->type = minor_num & 0x7;
	lunix_chrdev_state->buf_lim = 0;
	lunix_chrdev_state->buf_timestamp = 0;
	lunix_chrdev_state->raw_data = 0;
	filp->private_data = lunix_chrdev_state;
	debug("successfully allocated lunix_chrdev_state\n");
out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{

	/* ? */
	struct lunix_chrdev_state_struct *state;
	state = filp->private_data;
	WARN_ON(!state);

	kfree(state);

	printk(KERN_INFO "Lunix chatacter device closed successfully\n");
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	if (_IOC_TYPE(cmd) != LUNIX_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > LUNIX_IOC_MAXNR) return -ENOTTY;

	struct lunix_chrdev_state_struct *state;
	state = filp->private_data;
	switch(cmd) {
		case LUNIX_RAW_DATA:
			  down_interruptible(&state->lock);
				state->raw_data = (int) arg;
				up(&state->lock);
			  break;
		default:
				return -ENOTTY;
	}
	return 0;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;
	int flag;
	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	/* Lock? */
	down_interruptible(&state->lock);
	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if (*f_pos == 0) {
		while (lunix_chrdev_state_update(state) == -EAGAIN) {
			/* ? */
			/* The process needs to sleep */
			/* See LDD3, page 153 for a hint */
			up(&state->lock);
			debug("\"%s\" reading: going to sleep\n", current->comm);
			if (wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state)))
					return -ERESTARTSYS;
			if (down_interruptible(&state->lock))
				 	return -ERESTARTSYS;
		}
	}

	cnt = ( cnt >= state->buf_lim - *f_pos ? state->buf_lim - *f_pos : cnt );
	/* End of file */
	/* ? */

	/* Determine the number of cached bytes to copy to userspace */
	/* ? */



	if (copy_to_user(usrbuf, state->buf_data + *f_pos, cnt)) {
		ret = -EFAULT;
		goto out;
	}
	debug("We read %d bytes of data\n", cnt);
	*f_pos += cnt;
	ret = cnt;

	/* Auto-rewind on EOF mode? */
	/* ? */
	if (*f_pos == state->buf_lim) {
		*f_pos = 0;
	}
out:
	/* Unlock? */
	up(&state->lock);
	return ret;
}






static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{


  return 0;
}



static struct file_operations lunix_chrdev_fops =
{
  	.owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;

	debug("initializing character device\n");
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;

	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	/* ? */
	/* register_chrdev_region? */
	ret = register_chrdev_region(dev_no, lunix_minor_cnt, "lunix");
	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}
	/* ? */
	/* cdev_add? */
	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;

	debug("entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}
