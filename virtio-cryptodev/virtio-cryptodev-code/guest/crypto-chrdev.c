/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	int *host_fd;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[3];
	unsigned int num_out, num_in;
	struct virtqueue *vq;




	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor",
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}
	vq  = crdev->vq;
	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;
	/**
	 * We need two sg lists, one for syscall_type and one to get the
	 * file descriptor from the host.
	 **/
	/* ?? */
	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	num_out = 0;
	num_in = 0;

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;
	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	// lock lock lock
	if(down_interruptible(&crdev->lock)) {
		ret = -ERESTARTSYS;
		debug("open: down_interruptible");
		goto fail;
	}
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
													&syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;



	up(&crdev->lock);

	crof->host_fd = *host_fd;

	/* If host failed to open() return -ENODEV. */
	/* ?? */
	if (crof->host_fd == -1) {
		return -ENODEV;
	}
	debug("ola popa man moy ola komple me hostfd = %d", *host_fd);

	kfree(host_fd);
	kfree(syscall_type);

fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;

	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, host_fd_sg, host_ret_val_sg, *sgs[3];
	unsigned int *syscall_type;
	unsigned int num_out, num_in, len;
	int *host_fd, *host_ret_val;


	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;


	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	host_ret_val = kzalloc(sizeof(*host_ret_val), GFP_KERNEL);

	num_out = 0;
	num_in = 0;
	/**
	 * Send data to the host.
	 **/
	/* ?? */


	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	*host_fd = crof->host_fd;
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;

	sg_init_one(&host_ret_val_sg, host_ret_val, sizeof(*host_ret_val));
	sgs[num_out + num_in++] = &host_ret_val_sg;
	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	if(down_interruptible(&crdev->lock)) {
		ret = -ERESTARTSYS;
		debug("open: down_interruptible");
		goto fail;
	}
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
													&syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	up(&crdev->lock);

	if (*host_ret_val) {
		return -ENODEV;
	}
	kfree(syscall_type);
	kfree(host_fd);
	kfree(host_ret_val);
	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd,
                                unsigned long arg)
{
	long ret = 0;
	int err, data_size;
	struct crypt_op *temp_cryp;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, ioctl_cmd_sg, session_sg, sess_id_sg,
										 crypto_sg, host_fd_sg, host_ret_val_sg, sess_key_sg, cryp_src_sg,
										 cryp_iv_sg, cryp_dst_sg, *sgs[8];
	unsigned int num_out, num_in, len;
	unsigned char *sess_key, *cryp_src, *cryp_iv, *cryp_dst;
	unsigned int *syscall_type, *ioctl_cmd;
	struct session_op *sess;
	struct crypt_op *cryp;
	int *host_fd, *host_ret_val;
	__u32 *ses_id;
	cryp_dst = NULL;
	ses_id = NULL;
	cryp_iv = NULL;
	cryp_src = NULL;
	data_size = 0;
	debug("Entering");
	/**
	 * Allocate all data that will be sent to the host.
	 **/
	sess = kzalloc(sizeof(struct session_op), GFP_KERNEL);
	cryp = kzalloc(sizeof(struct crypt_op), GFP_KERNEL);

	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	ioctl_cmd = kzalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
	host_ret_val = kzalloc(sizeof(*host_ret_val), GFP_KERNEL);

	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;
	num_out = 0;
	num_in = 0;

	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	/* ?? */
	*host_fd = crof->host_fd;
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;
	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		*ioctl_cmd = IOCTL_CIOGSESSION;
		sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
		sgs[num_out++] = &ioctl_cmd_sg;
		if (copy_from_user(sess, (struct session_op*) arg, sizeof(struct session_op))) {
			return -EFAULT;
		}
		sess_key = kzalloc(sess->keylen, GFP_KERNEL);
		if (copy_from_user(sess_key, sess->key, sess->keylen)) {
			return -EFAULT;
		}
		//sess->key = sess_key;
		sg_init_one(&sess_key_sg, sess_key, sess->keylen);
		sgs[num_out++] = &sess_key_sg;
		sg_init_one(&session_sg, sess, sizeof(struct session_op));
		sgs[num_out + num_in++] = &session_sg;
		sg_init_one(&host_ret_val_sg, host_ret_val, sizeof(*host_ret_val));
		sgs[num_out + num_in++] = &host_ret_val_sg;

		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");
		*ioctl_cmd = IOCTL_CIOGFSESSION;
		sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
		sgs[num_out++] = &ioctl_cmd_sg;
		ses_id = kzalloc(sizeof(*ses_id), GFP_KERNEL);

		if (copy_from_user(ses_id, (__u32 *) arg, sizeof(*ses_id))) {
			return -EFAULT;
		}
		sg_init_one(&sess_id_sg, ses_id, sizeof(*ses_id));
		sgs[num_out++] = &sess_id_sg;

		sg_init_one(&host_ret_val_sg, host_ret_val, sizeof(*host_ret_val));
		sgs[num_out + num_in++] = &host_ret_val_sg;

		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		*ioctl_cmd = IOCTL_CIOCRYPT;
		sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
		sgs[num_out++] = &ioctl_cmd_sg;

		if (copy_from_user(cryp, (struct crypt_op*) arg, sizeof(struct crypt_op))) {
			return -EFAULT;
		}
		data_size = cryp->len;
		cryp_dst = kzalloc(data_size, GFP_KERNEL);
		cryp_iv = kzalloc(VIRTIO_CRYPTODEV_BLOCK_SIZE, GFP_KERNEL);
		cryp_src = kzalloc(data_size, GFP_KERNEL);

		sg_init_one(&crypto_sg, cryp, sizeof(struct crypt_op));
		sgs[num_out++] = &crypto_sg;

		if (copy_from_user(cryp_src, cryp->src, data_size)) {
			return -EFAULT;
		}
		sg_init_one(&cryp_src_sg, cryp_src, data_size);
		sgs[num_out++] = &cryp_src_sg;

		if (copy_from_user(cryp_iv, cryp->iv, VIRTIO_CRYPTODEV_BLOCK_SIZE)) {
			return -EFAULT;
		}

		sg_init_one(&cryp_iv_sg, cryp_iv, VIRTIO_CRYPTODEV_BLOCK_SIZE);
		sgs[num_out++] = &cryp_iv_sg;

		sg_init_one(&cryp_dst_sg, cryp_dst, data_size);
		sgs[num_out + num_in++] = &cryp_dst_sg;

		sg_init_one(&host_ret_val_sg, host_ret_val, sizeof(*host_ret_val));
		sgs[num_out + num_in++] = &host_ret_val_sg;

		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}


	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */
	if(down_interruptible(&crdev->lock)) {
		ret = -ERESTARTSYS;
		debug("open: down_interruptible");
		goto fail;
	}
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	up(&crdev->lock);


	switch (cmd) {
		case CIOCGSESSION:
			if (*host_ret_val != 0) {
				return -ENODEV;
			}
			if (copy_to_user((struct session_op*) arg, sess, sizeof(struct session_op))) {
				return -EFAULT;
			}
			break;
		case CIOCFSESSION:
			if (*host_ret_val != 0) {
				return -ENODEV;
			}
			kfree(ses_id);
			break;
		case CIOCCRYPT:
			if (*host_ret_val != 0) {
				return -ENODEV;
			}
			temp_cryp = (struct crypt_op*)arg;
			if (copy_to_user(temp_cryp->dst, cryp_dst, data_size)) {
				return -EFAULT;
			}
			kfree(cryp_dst);
			kfree(cryp_iv);
			kfree(cryp_src);
			break;
		default:
			debug("Unsupported ioctl command");

	}
	kfree(syscall_type);
	kfree(host_fd);
	kfree(host_ret_val);
	kfree(ioctl_cmd);
	kfree(sess);
	kfree(cryp);

	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf,
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops =
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;

	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
