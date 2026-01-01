#metadata(
  (
    title: "Device Driver Lifecycle",
    description: "Understanding the lifecycle of a Linux character device driver and how to interact with it.",
    date: "2026-01-01",
    order: 3,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Device Driver Lifecycle

This guide explains the lifecycle of a Linux character device driver using a simple example. We will cover how the kernel module is initialized, how it handles file operations (open, read, write, release), and how to interact with it from user space.

The source code for this example is available in #link("https://github.com/fepfitra/kernel-pwn-minimal/blob/master/src/hello_dev_char.c")[`hello_dev_char.c`].

== The Driver Code
```c
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

static int major_number;

// Called when the device is opened (e.g., fopen / open)
static int device_open(struct inode *inode, struct file *filp) {
  printk(KERN_ALERT "Device opened.");
  return 0;
}

// Called when the device is closed (e.g., fclose / close)
static int device_release(struct inode *inode, struct file *filp) {
  printk(KERN_ALERT "Device closed.");
  return 0;
}

// Called when data is read from the device (e.g., fread / read)
static ssize_t device_read(struct file *filp, char *buffer, size_t length,
                           loff_t *offset) {
  char *msg = "Hello kernel-pwn!\n";
  // copy_to_user returns the number of bytes that *failed* to copy.
  // We want to return the number of bytes successfully copied.
  return strlen(msg) - copy_to_user(buffer, msg, strlen(msg));
}

// Called when data is written to the device (e.g., fwrite / write)
static ssize_t device_write(struct file *filp, const char *buf, size_t len,
                            loff_t *off) {
  printk(KERN_ALERT "Sorry, this operation isn't supported.\n");
  return -EINVAL;
}

// Mapping file operations to our functions
static struct file_operations fops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release
};
// Module Initialization
int init_module(void) {
  // 0 requests dynamic allocation of a major number
  major_number = register_chrdev(0, "hello_dev_char", &fops);

  if (major_number < 0) {
    printk(KERN_ALERT "Registering char device failed with %d\n", major_number);
    return major_number;
  }

  printk(KERN_INFO "I was assigned major number %d.\n", major_number);
  printk(KERN_INFO "Create device with: 'mknod /dev/hello_dev_char c %d 0'.\n", major_number);
  return 0;
}

// Module Cleanup
void cleanup_module(void) {
  unregister_chrdev(major_number, "hello_dev_char");
}
```

== Lifecycle Stages

1. *Initialization (`init_module`)*:
  - When the module is loaded (e.g., via `insmod`), `init_module` is executed.
  - It registers the character device using `register_chrdev`, dynamically obtaining a *major number*.
  - The `file_operations` structure (`fops`) links system calls (open, read, write) to the driver's functions.

2. *Device Creation (Manual)*:

  - The driver prints the assigned major number to the kernel log (`dmesg`).

  - *Crucial Note*: `register_chrdev` only registers the driver's intent to handle a major number in the kernel's internal tables. It does *not* create a file in `/dev`.

  - A device node must be created manually in `/dev` using `mknod` to allow user-space interaction:

    ```bash
    mknod /dev/hello_dev_char c <major_number> 0 #look up major_number from dmesg
    ```



  === Why isn't it automatic?

  In modern Linux drivers, automatic device node creation is handled by the `udev` daemon (or `mdev` in BusyBox). To enable this, the driver must:

  1. Create a class using `class_create()`.

  2. Create a device within that class using `device_create()`.



When these functions are called, the kernel sends a "uevent" to user space, and `udev` automatically creates the `/dev` node with the correct major/minor numbers. Since this is a "minimal" driver, we perform this step manually.



3. *Operational Phase (Event Handling)*:
  These functions are *not* called directly by `init_module`. Instead, they were registered in Step 1 and are now invoked by the kernel in response to user-space actions.

  - *Open (`device_open`)*: Triggered when a process opens the device file.
  - *Read (`device_read`)*: Triggered when a process reads from the device. It uses `copy_to_user` to safely transfer data from kernel space to user space.
  - *Write (`device_write`)*: Triggered when a process writes to the device. In this example, it returns `-EINVAL` (Invalid Argument).
  - *Release (`device_release`)*: Triggered when the file descriptor is closed.

4. *Cleanup (`cleanup_module`)*:
  - When the module is unloaded (e.g., via `rmmod`), `cleanup_module` is called.
  - It unregisters the device, freeing the major number.

== Interaction Example

```bash
# 1. Load the kernel module
insmod hello_dev_char.ko

# 2. Find the assigned major number
dmesg | tail -n 2
# [   11.031500] I was assigned major number 248.
# [   11.031588] Create device with: 'mknod /dev/hello_dev_char c 248 0'.

# 3. Create the device node (using the major number from dmesg)
mknod /dev/hello_dev_char c 248 0

# 4. Read from the device
cat /dev/hello_dev_char
# Hello hello-dev!
# [   98.468344] Device opened.

# 5. Write to the device
echo "test" > /dev/hello_dev_char
# [   39.914686] Device closed.
# [   64.052574] Device opened.
# [   64.054854] Sorry, this operation isn't supported.

# 6. Check detailed logs
dmesg | tail
```

== Interaction with C

You can also interact with the device driver using standard C library functions (`open`, `read`, `write`, `close`).

```c
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DEVICE "/dev/hello-dev-char"

int main() {
  int fd;
  char buffer[1024];

  printf("Opening device %s...\n", DEVICE);
  fd = open(DEVICE, O_RDWR); // Open the device
  if (fd < 0) {
    perror("Failed to open device");
    return 1;
  }
  printf("Device opened successfully.\n");

  printf("Reading from device...\n");
  ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1); //Read from the device
  if (bytes_read < 0) {
    perror("Failed to read from device");
  } else {
    buffer[bytes_read] = '\0';
    printf("Read %zd bytes: %s\n", bytes_read, buffer);
  }

  printf("Writing to device...\n");
  const char *msg = "Hello Kernel!";
  write(fd, msg, strlen(msg)); //Write to the device

  printf("Closing device...\n");
  close(fd); //Close the device

  return 0;
}
```
Place this code into exploit folder and run `pack.sh` to compile and include it in the initramfs. Then run `./run.sh` to test it in the QEMU environment. Don't forget to create the device node in `/dev` first!
