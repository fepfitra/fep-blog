---
title: "Secret Procfs Challenge"
description: "A deep dive into kernel procfs interaction and simple authentication mechanisms."
date: "2026-01-05"
order: 6
draft: false
---

# Secret Procfs Challenge: Kernel-Space Authentication

This challenge explores the implementation of a virtual file interface within the Linux kernel using the `/proc` filesystem. Unlike standard files, `/proc` entries are windows into the kernel's state, where "reads" and "writes" trigger direct execution of kernel-mode functions.

## Internal Mechanism

The challenge centers on a kernel module that gates access to a "flag" based on a session-wide `authenticated` state. This state is toggled by writing a specific password to the proc entry.

### Kernel-User Data Transfer

A critical concept in kernel exploitation is the separation of memory spaces. The kernel cannot directly dereference user-space pointers because they may be invalid, paged out, or malicious. Instead, it uses specialized functions:

- **`copy_from_user(to, from, n)`**: Safely copies $n$ bytes from user-space address `from` to kernel-space address `to`.
- **`copy_to_user(to, from, n)`**: Safely copies $n$ bytes from kernel-space address `from` to user-space address `to`.

In this challenge, these functions are used to ingest the password and output the flag.

## The Driver Code

The module defines two primary callback functions: `device_read` and `device_write`, which are linked to the VFS via the `proc_ops` structure.

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define PROC_FILENAME "pwnmepls"
#define PASSWORD "uiiaiiuuiiai"
#define FLAG "well done baby\n"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fitrafep");
MODULE_DESCRIPTION("Secret Procfs Challenge");

static struct proc_dir_entry *proc_entry;
static int authenticated = 0; // The "gatekeeper" state

/**
 * device_read: Triggered by cat /proc/pwnmepls or read() syscall.
 */
static ssize_t device_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    const char *flag_str = FLAG;
    size_t flag_len = strlen(flag_str);

    // If not authenticated, return a hint instead of the flag
    if (!authenticated) {
        const char *msg = "Password required. Write the password to this file first.\n";
        size_t msg_len = strlen(msg);
        if (*offset >= msg_len) return 0;
        if (length > msg_len - *offset) length = msg_len - *offset;
        if (copy_to_user(buffer, msg + *offset, length)) return -EFAULT;
        *offset += length;
        return length;
    }

    // Standard read logic for returning the flag
    if (*offset >= flag_len) return 0;
    if (length > flag_len - *offset) length = flag_len - *offset;
    if (copy_to_user(buffer, flag_str + *offset, length)) return -EFAULT;

    *offset += length;
    return length;
}

/**
 * device_write: Triggered by echo "pass" > /proc/pwnmepls or write() syscall.
 */
static ssize_t device_write(struct file *filp, const char __user *buff, size_t len, loff_t *off)
{
    char input[32];
    size_t pass_len = strlen(PASSWORD);

    if (len > sizeof(input) - 1) return -EINVAL;

    // Safely bring the password into kernel memory
    if (copy_from_user(input, buff, len)) return -EFAULT;

    input[len] = '\0'; // Ensure null-termination

    // Check password and update state
    if (len >= pass_len && strncmp(input, PASSWORD, pass_len) == 0) {
        authenticated = 1;
        printk(KERN_INFO "secret_chall: Correct password!\n");
    } else {
        authenticated = 0;
        printk(KERN_INFO "secret_chall: Incorrect password.\n");
    }

    return len;
}

/* Compatibility for newer kernels (proc_ops) and older kernels (file_operations) */
#ifdef HAVE_PROC_OPS
static const struct proc_ops proc_fops = {
    .proc_read = device_read,
    .proc_write = device_write,
};
#else
static const struct file_operations proc_fops = {
    .read = device_read,
    .write = device_write,
};
#endif

static int __init secret_chall_init(void) {
    proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &proc_fops);
    return proc_entry ? 0 : -ENOMEM;
}

static void __exit secret_chall_exit(void) {
    if (proc_entry) proc_remove(proc_entry);
}

module_init(secret_chall_init);
module_exit(secret_chall_exit);
```

## Makefile

```makefile
obj-m += secret_chall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

## Analysis of Operations

### 1. Writing the Password (`device_write`)

When you run `echo -n "password" > /proc/pwnmepls`, the kernel invokes `device_write`.
- The `buff` pointer is in **user-space**. The module uses `copy_from_user` to pull it into the kernel stack (`input[32]`).
- It uses `strncmp` to compare the input against the hardcoded `PASSWORD`.
- If they match, it sets `authenticated = 1`. This variable is stored in the kernel's data segment, making it persistent across different process interactions until the module is unloaded.

### 2. Reading the Flag (`device_read`)

When you run `cat /proc/pwnmepls`, the kernel invokes `device_read`.
- It first checks the global `authenticated` flag.
- If `0`, it prepares a "hint" message.
- If `1`, it prepares the `FLAG` string.
- It uses `copy_to_user` to transfer the chosen string into the user-space buffer provided by `cat`.
- The `offset` parameter ensures that multiple `read()` calls (e.g., if the buffer is small) correctly progress through the string.

## Exploitation Plan

The "exploit" is a simple two-step protocol:
1. **Authentication**: Send the magic string `uiiaiiuuiiai` to the kernel.
2. **Retrieval**: Read the resulting state update.

### Solve Script (Bash)

```bash
# -n is important to avoid sending a trailing newline unless the driver expects it
echo -n "uiiaiiuuiiai" > /proc/pwnmepls
cat /proc/pwnmepls
```

### Solve Script (C)

A C-based solve is more robust for complex interactions.

```c
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
    // 1. Write the secret password
    int fd = open("/proc/pwnmepls", O_WRONLY);
    if (fd < 0) { perror("open write"); return 1; }

    const char *password = "uiiaiiuuiiai";
    write(fd, password, strlen(password));
    close(fd);

    // 2. Read the unlocked flag
    fd = open("/proc/pwnmepls", O_RDONLY);
    if (fd < 0) { perror("open read"); return 1; }

    char buf[256] = {0};
    read(fd, buf, sizeof(buf) - 1);
    printf("Flag: %s\n", buf);

    close(fd);
    return 0;
}
```

## Summary of Kernel Concepts

- **VFS (Virtual File System)**: The abstraction layer that allows the module to present a "file" interface for functional code.
- **Procfs**: A specific VFS implementation for kernel/user communication.
- **User/Kernel Boundary**: The strict wall enforced by hardware and crossed safely via `copy_to/from_user`.
- **Module State**: Variables like `authenticated` reside in kernel memory and persist across multiple user-space system calls.

## Deployment

To deploy this challenge using the [kernel-pwn-minimal](https://github.com/fepfitra/kernel-pwn-minimal) orchestrator, place the challenge source code in the `src/` directory and your exploit source in the `exploit/` directory.

Modify the `rootfs/init` script to load the module and trigger the exploit automatically:

```diff
 -exec /bin/sh
 +insmod /secret_chall.ko
 +/exploit_secret
 +/exploit_secret.sh
 +poweroff -f
```

Finally, rebuild the rootfs and launch the environment:

```bash
./pack.sh && ./run.sh
```
