#metadata(
  (
    title: "Proc Filesystem Interaction",
    description: "Creating and interacting with kernel modules via the /proc filesystem.",
    date: "2026-01-01",
    order: 5,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Proc Filesystem Interaction

The `/proc` filesystem is a virtual filesystem in Linux that provides an interface to kernel data structures. While primarily used for process information (hence the name), it is also commonly used by kernel modules to provide simple interfaces without managing major/minor numbers or device nodes manually.

== The Driver Code

This driver is functionally similar to the character device example but registers itself under `/proc` using `proc_create`.

```c
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

static int device_open(struct inode *inode, struct file *filp) {
  printk(KERN_ALERT "Device opened.");
  return 0;
}

static int device_release(struct inode *inode, struct file *filp) {
  printk(KERN_ALERT "Device closed.");
  return 0;
}

static ssize_t device_read(struct file *filp, char *buffer, size_t length,
                           loff_t *offset) {
  char *msg = "Hello kernel-pwn!\n";
  // copy_to_user returns the number of bytes that *failed* to copy.
  // We want to return the number of bytes successfully copied.
  return strlen(msg) - copy_to_user(buffer, msg, strlen(msg));
}

static ssize_t device_write(struct file *filp, const char *buf, size_t len,
                            loff_t *off) {
  printk(KERN_ALERT "Sorry, this operation isn't supported.\n");
  return -EINVAL;
}

static struct file_operations fops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release
};

struct proc_dir_entry *proc_entry = NULL;

int init_module(void) {
  // Create /proc/kernel-pwn-char with rw-rw-rw- permissions
  proc_entry = proc_create("kernel-pwn-char", 0666, NULL, &fops);
  printk(KERN_ALERT "/proc/kernel-pwn-char created!");
  return 0;
}

void cleanup_module(void) {
  if (proc_entry)
    proc_remove(proc_entry);
  printk(KERN_ALERT "/proc/kernel-pwn-char removed!");
}
```

== Lifecycle Stages

1.  *Initialization (`init_module`)*:
    -   When the module is loaded, `init_module` is executed.
    -   It uses `proc_create` to register a new entry in the `/proc` filesystem.
    -   It assigns the `file_operations` structure (`fops`) to this entry, linking the `read` and `write` system calls to the driver's functions.

2.  *Operational Phase (Event Handling)*:
    These functions are callbacks invoked by the kernel when users interact with `/proc/kernel-pwn-char`.
    -   *Open (`device_open`)*: Triggered when the file is opened.
    -   *Read (`device_read`)*: Triggered when reading from the file. It copies data to user space.
    -   *Write (`device_write`)*: Triggered when writing to the file. Returns `-EINVAL` in this example.
    -   *Release (`device_release`)*: Triggered when the file is closed.

3.  *Cleanup (`cleanup_module`)*:
    -   When the module is unloaded, `cleanup_module` runs.
    -   It calls `proc_remove` to delete the entry from the `/proc` filesystem, ensuring no stale entries remain.

== Key Differences from Character Devices

1. *No Major/Minor Numbers*: You don't need `register_chrdev`. `proc_create` handles the VFS registration directly.
2. *Automatic Node Creation*: The file `/proc/kernel-pwn-char` appears automatically when the module is loaded. You do *not* need to run `mknod`.
3. *Permissions*: The second argument to `proc_create` (`0666`) sets the file permissions (read/write for everyone).

== Interaction Example (Bash)

Since it's just a file in `/proc`, you can interact with it using standard tools like `cat` and `echo`.

```bash
# 1. Load the module
insmod proc_mod.ko
dmesg | tail -n 1
# Output: /proc/kernel-pwn-char created!

# 2. Check if the file exists
ls -l /proc/kernel-pwn-char
# Output: -rw-rw-rw-    1 root     root             0 Jan  1 00:00 /proc/kernel-pwn-char

# 3. Read from the file
cat /proc/kernel-pwn-char
# Output: Hello kernel-pwn!

# 4. Write to the file (fails as expected)
echo "test" > /proc/kernel-pwn-char
# Output: write error: Invalid argument
```

== Interaction with C

The C interaction is identical to any other file interaction. You simply open the path `/proc/kernel-pwn-char`.

```c
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PROC_FILE "/proc/kernel-pwn-char"

int main() {
  int fd;
  char buffer[1024];

  // 1. Open the proc file
  printf("Opening %s...\n", PROC_FILE);
  fd = open(PROC_FILE, O_RDWR);
  if (fd < 0) {
    perror("Failed to open proc file");
    return 1;
  }
  printf("Opened successfully.\n");

  // 2. Read from the file
  printf("Reading...\n");
  ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
  if (bytes_read < 0) {
    perror("Failed to read");
  } else {
    buffer[bytes_read] = '\0';
    printf("Read %zd bytes: %s\n", bytes_read, buffer);
  }

  // 3. Write to the file
  printf("Writing...\n");
  const char *msg = "Testing write";
  ssize_t bytes_written = write(fd, msg, strlen(msg));
  if (bytes_written < 0) {
    perror("Failed to write (expected)");
  }

  close(fd);
  return 0;
}
```
