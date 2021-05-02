/*
 * Virtio Cryptodev Device
 *
 * Implementation of virtio-cryptodev qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr> 
 * Konstantinos Papazafeiropoulos <kpapazaf@cslab.ece.ntua.gr>
 *
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "hw/qdev.h"
#include "hw/virtio/virtio.h"
#include "standard-headers/linux/virtio_ids.h"
#include "hw/virtio/virtio-cryptodev.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>


#define DATA_SIZE       16384
#define BLOCK_SIZE      16
#define KEY_SIZE        24

static uint64_t get_features(VirtIODevice *vdev, uint64_t features,
                             Error **errp)
{
    DEBUG_IN();
    return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
    DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
    DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
    DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtQueueElement *elem;
    unsigned int *syscall_type;
    int *host_fd, *ioctl_cmd, *host_ret_val, *ses_id;
    struct session_op *sess_ptr;
    struct crypt_op  *cryp_ptr;
    DEBUG_IN();

    elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
    if (!elem) {
        DEBUG("No item to pop from VQ :(");
        return;
    } 

    DEBUG("I have got an item from VQ :)");

    syscall_type = elem->out_sg[0].iov_base;
    switch (*syscall_type) {
    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN");
	DEBUG("hello world");
	int cfd = open("/dev/crypto", O_RDWR);
	host_fd = elem->in_sg[0].iov_base;
	*host_fd = cfd;

	DEBUG("host_fd epityxiaaaa");
        
        break;

    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE");
        host_fd = elem->out_sg[1].iov_base;
        host_ret_val = elem->in_sg[0].iov_base;
        if ((*host_ret_val = close(*host_fd))) {
        	perror("close(fd)");
        }

        break;

    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL");
        host_fd = elem->out_sg[1].iov_base;
        ioctl_cmd = elem->out_sg[2].iov_base;
     
        
        switch (*ioctl_cmd) {
        case 0:
        	DEBUG("we are in ciogsession bitches");
        	sess_ptr = elem->in_sg[0].iov_base;
        	sess_ptr->key = elem->out_sg[3].iov_base;
        	host_ret_val = elem->in_sg[1].iov_base;
        	if ((*host_ret_val = ioctl(*host_fd, CIOCGSESSION, sess_ptr))) {
				perror("ioctl(CIOCGSESSION)");

			}

			DEBUG("EEE AN GINEI KAI AYTO OLA YPERPOPA");
			break;
		case 1: 
			ses_id = elem->out_sg[3].iov_base;
			host_ret_val = elem->in_sg[0].iov_base;
			if ((*host_ret_val = ioctl(*host_fd, CIOCFSESSION, ses_id))) {
				perror("ioctl(CIOCFSESSION)");
			}
			break;
		case 2:
			DEBUG("we are in ciocrypt");
			cryp_ptr = (struct crypt_op *) elem->out_sg[3].iov_base;
			cryp_ptr->src = elem->out_sg[4].iov_base;
			cryp_ptr->iv = elem->out_sg[5].iov_base;
			cryp_ptr->dst = elem->in_sg[0].iov_base;
			host_ret_val = elem->in_sg[1].iov_base;
			
			if ((*host_ret_val = ioctl(*host_fd, CIOCCRYPT, cryp_ptr))) {
				perror("ioctl(CIOCCRYPT)");
			}
			DEBUG("OKAY CRYPTOGRAPHY HAPPENED, WE ARE GOOD");
			
			DEBUG("OLA POPA AGAIN");

			break;
		default:
			DEBUG("NOT VALID IOCTL command");
			break;	
		}
		
			
        	
        	 
        	
        	
        /* ?? */
        /*unsigned char *output_msg = elem->out_sg[1].iov_base;
        unsigned char *input_msg = elem->in_sg[0].iov_base;
        memcpy(input_msg, "Host: Welcome to the virtio World!", 35);
        printf("Guest says: %s\n", output_msg);
        printf("We say: %s\n", input_msg);*/
        break;

    default:
        DEBUG("Unknown syscall_type");
        break;
    }

    virtqueue_push(vq, elem, 0);
    virtio_notify(vdev, vq);
    g_free(elem);
}

static void virtio_cryptodev_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    DEBUG_IN();

    virtio_init(vdev, "virtio-cryptodev", VIRTIO_ID_CRYPTODEV, 0);
    virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_cryptodev_unrealize(DeviceState *dev, Error **errp)
{
    DEBUG_IN();
}

static Property virtio_cryptodev_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_cryptodev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

    DEBUG_IN();
    dc->props = virtio_cryptodev_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_cryptodev_realize;
    k->unrealize = virtio_cryptodev_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_cryptodev_info = {
    .name          = TYPE_VIRTIO_CRYPTODEV,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCryptodev),
    .class_init    = virtio_cryptodev_class_init,
};

static void virtio_cryptodev_register_types(void)
{
    type_register_static(&virtio_cryptodev_info);
}

type_init(virtio_cryptodev_register_types)
