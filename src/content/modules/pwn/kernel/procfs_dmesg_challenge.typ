#metadata(
  (
    title: "Procfs Dmesg Challenge",
    description: "A variation of the procfs challenge where the flag is leaked to the kernel log.",
    date: "2026-01-05",
    order: 8,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Procfs Dmesg Challenge: Information Leakage

In this challenge, the kernel module not only provides a file interface but also leaks sensitive information (the flag) directly into the kernel's circular log buffer via `printk`.

== The Driver Code

The module creates `/proc/pwnmepls`. Upon receiving the correct password, it logs the flag to the kernel buffer.

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
#define FLAG "well done baby\n"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fitrafep");
MODULE_DESCRIPTION("Procfs Dmesg Challenge");

static struct proc_dir_entry *proc_entry;
static int authenticated = 0;

static ssize_t device_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    const char *flag_str = FLAG;
    size_t flag_len = strlen(flag_str);

    if (!authenticated) {
        return -EACCES;
    }

    if (*offset >= flag_len)
        return 0;

    if (length > flag_len - *offset)
        length = flag_len - *offset;

    if (copy_to_user(buffer, flag_str + *offset, length))
        return -EFAULT;

    *offset += length;
    return length;
}

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
        printk(KERN_INFO "secret_chall: Correct! Flag: %s\n", FLAG);
    } else {
        authenticated = 0;
        printk(KERN_INFO "secret_chall: Incorrect password.\n");
    }

    return len;
}

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

== The Kernel Log Leak

The interesting part of this challenge is how the flag is disclosed:

```c
printk(KERN_INFO "secret_chall: Correct! Flag: %s\n", FLAG);
```

- *`printk()`*: This is the kernel's version of `printf()`. Instead of writing to standard output (which doesn't exist for the kernel), it writes messages to the **kernel circular buffer**.
- *`KERN_INFO`*: This is a log level macro. It categorizes the message as informational.
- *Visibility*: Messages in the kernel buffer are not directly visible to user processes. However, the `dmesg` utility (or reading `/proc/kmsg`) allows users to dump the contents of this buffer.

In many real-world scenarios, developers accidentally leave sensitive information (like memory addresses or even keys) in debug `printk` statements, which can be harvested by attackers to bypass mitigations like KASLR.

== Exploit Script (C)

This script interacts with the proc entry and instructs the user to check the kernel logs for the flag.

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("[*] Current UID: %d\n", getuid());

    int fd = open("/proc/pwnmepls", O_WRONLY);
    if (fd < 0) {
        perror("open /proc/pwnmepls");
        return 1;
    }

    const char *password = "uiiaiiuuiiai";
    if (write(fd, password, strlen(password)) < 0) {
        perror("write password");
        close(fd);
        return 1;
    }
    close(fd);

    printf("[+] Password sent. Checking dmesg for the flag...\n");

    return 0;
}
```

== Solve via Bash

You can solve this by sending the password and then either reading the file or checking the kernel log via `dmesg`.

```bash
echo -n "uiiaiiuuiiai" > /proc/pwnmepls
cat /proc/pwnmepls
# OR
dmesg | tail
```

