#include <linux/kernel.h> /* We.re doing kernel work */
#include <linux/module.h> /* Specifically, a module */
#include <linux/fs.h>
#include <linux/wrapper.h> 


/* Device Declarations */
/* The name for our device, as it will appear
/* in /proc/devices */
#define DEVICE_NAME "jodie"
#define BUF_LEN 80

/* Used to prevent */
/* concurent access into the same device */
static int Device_Open = 0;

/* The message the device will give when asked */
static char Message[BUF_LEN];
static char *Message_Ptr;

/*
 * This function is called whenever a process
 * attempts to open the device file
 */
static int device_open(struct inode *inode, struct file *file)
{
	static int counter = 0;
	printk("device_open(%p,%p)\n", inode, file);
	printk("Device: %d.%d\n.", inode->i_rdev >> 8, inode->i_rdev & 0xFF);

	if (Device_Open)
		return -EBUSY;
	Device_Open++;
	sprintf(Message,
	counter++,
	Message_Ptr = Message;
	MOD_INC_USE_COUNT;
	return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file)
{
	Device_Open --;
	MOD_DEC_USE_COUNT;
	return 0;
}

static ssize_t device_read(
	struct file *file,
	char *buffer, 		/* The buffer to fill with data */
	size_t length, 		/* The length of the buffer */
	loff_t *offset) 	/* Our offset in the file */
{
	/* Number of bytes actually written to the buffer */
	int bytes_read = 0;

	/* If we.re at the end of the message, return 0
	if (*Message_Ptr == 0)
	return 0;

	/* Actually put the data into the buffer */
	while (length && *Message_Ptr) {
		put_user(*(Message_Ptr++), buffer++);
		length --;
		bytes_read ++;
	}

	printk ("Read %d bytes, %d left\n", bytes_read, length);
	return bytes_read;
}

static ssize_t device_write(
	struct file *file,
	const char *buffer, 	/* The buffer */
	size_t length, 		/* The length of the buffer */
	loff_t *offset) 	/* Our offset in the file */
{
	return -EINVAL;
}

/* Module Declarations */
struct file_operations Fops = {
		NULL, /* seek */
		device_read,
		device_write,
		NULL, /* readdir */
		NULL, /* select */
		NULL, /* ioctl */
		NULL, /* mmap */
		device_open,
		NULL, /* flush */
		device_release /* a.k.a. close */
};

/* Initialize the module - Register the character device */
int init_module()
{
	/* Register the character device */
	Major = module_register_chrdev(0, DEVICE_NAME, &Fops);

	/* Negative values signify an error */
	if (Major < 0) {
		printk ("%s device failed with %d\n", "Sorry, registering the character", Major);
		return Major;
	}
	return 0;
}

/* Cleanup - unregister the appropriate file from /proc */
void cleanup_module()
{
	int ret;
	/* Unregister the device */
	ret = module_unregister_chrdev(Major, DEVICE_NAME);
	if (ret < 0)
		printk("Error in unregister_chrdev: %d\n", ret);
}
