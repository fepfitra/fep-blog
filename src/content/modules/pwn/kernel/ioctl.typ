#metadata(
  (
    title: "IOCTL Interaction",
    description: "Understanding and exploiting IOCTL interfaces in Linux kernel drivers.",
    date: "2026-01-01",
    order: 4,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= IOCTL Interaction

`ioctl` (Input/Output Control) is a system call for device-specific input/output operations and other operations which cannot be expressed by regular system calls. It is a common attack surface in kernel exploitation because it often handles complex structures and commands.

This example demonstrates a vulnerable driver that uses `ioctl` to gatekeep a flag behind a password check.

== The Driver Code

```c
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/ioctl.h>

#define PWN_GET _IO('p', 1)
#define PWN_SET _IO('p', 2)

MODULE_LICENSE("GPL");

char flag[128];
static int device_open(struct inode *inode, struct file *filp)
{
    	printk(KERN_ALERT "Device opened.\n");
  	return 0;
}

static int device_release(struct inode *inode, struct file *filp)
{
    	printk(KERN_ALERT "Device closed.\n");
  	return 0;
}

static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
	return -EINVAL;
}

static ssize_t device_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
  	return -EINVAL;
}

char message[16];
static long device_ioctl(struct file *filp, unsigned int ioctl_num, unsigned long ioctl_param)
{
	int is_copy_invalid = 0;
	printk(KERN_ALERT "Got ioctl argument %#x!\n", ioctl_num);
	if (ioctl_num == PWN_GET && strcmp(message, "PASSWORD") == 0) {
		printk(KERN_ALERT "Writing to userspace!\n");
		is_copy_invalid = copy_to_user((char *)ioctl_param, flag, 128);
	} else if (ioctl_num == PWN_SET) {
		printk(KERN_ALERT "Reading from userspace!\n");
		is_copy_invalid = copy_from_user(message, (char *)ioctl_param, 16);
	}

	if (is_copy_invalid)
		return -EFAULT;
	return 0;
}

static struct file_operations fops = {
  	.read = device_read,
  	.write = device_write,
  	.unlocked_ioctl = device_ioctl,
  	.open = device_open,
  	.release = device_release
};

struct proc_dir_entry *proc_entry = NULL;

int init_module(void)
{
	// read in flag file
	loff_t offset = 0;
	struct file *flag_fd;
	flag_fd = filp_open("/flag", O_RDONLY, 0);
	kernel_read(flag_fd, flag, 128, &offset);
	filp_close(flag_fd, NULL);

	printk(KERN_ALERT "ioctl address: %#lx\b", (unsigned long)device_ioctl);
	printk(KERN_ALERT "PWN_GET value: %#x\b", PWN_GET);
	printk(KERN_ALERT "PWN_SET value: %#x\b", PWN_SET);
    	proc_entry = proc_create("kernel-pwn-ioctl", 0666, NULL, &fops);
  	return 0;
}

void cleanup_module(void)
{
	if (proc_entry) proc_remove(proc_entry);
}
```

== Lifecycle Stages

1.  *Initialization (`init_module`)*:
    -   Reads the flag from `/flag` into a kernel buffer.
    -   Registers the device in `/proc` using `proc_create`.
    -   Prints debug info (ioctl address, command values) to `dmesg`.

2.  *Operational Phase (Event Handling)*:
    -   *IOCTL (`device_ioctl`)*: The core function triggered by the `ioctl` system call.
        -   `PWN_SET`: Copies data *from* user space (write).
        -   `PWN_GET`: Copies data *to* user space (read), gated by a password check.
    -   *Open/Release*: Simple logging stubs.

3.  *Cleanup (`cleanup_module`)*:
    -   Removes the `/proc` entry.

== Analysis

Unlike the previous character device which used `register_chrdev`, this driver uses `proc_create` to create an entry in the `/proc` filesystem. This means:
1. The device path is `/proc/kernel-pwn-ioctl`.
2. It does not require manual `mknod` or a major number; the kernel handles the VFS entry.

The core logic lies in `device_ioctl`. It defines two commands:
- `PWN_SET`: Copies 16 bytes from user space into the global `message` buffer.
- `PWN_GET`: Checks if `message` equals "PASSWORD". If true, it copies the `flag` to user space.

== Difference between IOCTL and Regular Character Drivers

While standard character drivers primarily use `read` and `write` operations to transfer streams of data (like a file pipe), `ioctl` serves a different purpose:

-   *Control Plane*: `ioctl` is designed for "out-of-band" control operations. For example, changing the baud rate of a serial port, ejecting a CD-ROM, or in our case, setting a password.
-   *Structured Data*: `read`/`write` typically handle unstructured byte streams. `ioctl` allows passing complex structures or specific command codes (`cmd`) to trigger distinct actions within the driver.
-   *Multiplexing*: A single `ioctl` function can handle hundreds of different operations via a `switch` statement on the command argument, whereas `read`/`write` are single-purpose.

In exploitation, `ioctl` handlers are often rich targets because they implement complex state machines and parsing logic that are more prone to logic bugs or memory corruption than simple read/write buffers.

== Interaction with C

To interact with this driver, we need to issue `ioctl` syscalls. We must set the `message` to "PASSWORD" first, then request the flag.

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// Define commands exactly as in the driver
#define PWN_GET _IO('p', 1)
#define PWN_SET _IO('p', 2)

int main() {
    printf("[*] Opening driver...\n");
    int fd = open("/proc/kernel-pwn-ioctl", O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }

    char buffer[128];
    char *pass = "PASSWORD";

    // 1. Set the password
    printf("[*] Sending password: %s\n", pass);
    if (ioctl(fd, PWN_SET, pass) < 0) {
        perror("ioctl PWN_SET failed");
        return 1;
    }

    // 2. Retrieve the flag
    printf("[*] Retrieving flag...\n");
    // We pass the buffer address where the flag should be written
    if (ioctl(fd, PWN_GET, buffer) < 0) {
        perror("ioctl PWN_GET failed");
        return 1;
    }

    printf("[+] Flag: %s\n", buffer);

    close(fd);
    return 0;
}
```

=== Steps to Run
1. Save the interaction code as `exploit/exploit.c`.
2. Ensure your environment has a `/flag` file (the driver tries to read it on load).
3. Run `./pack.sh` to compile and build the rootfs.
4. Run `./run.sh` to start QEMU.
5. Execute `./exploit` inside the VM.

