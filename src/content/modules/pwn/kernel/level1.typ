#metadata(
  (
    title: "Kernel Level 1",
    description: "Writeup for Kernel Level 1",
    date: "2026-01-01",
    order: 1,
    draft: true,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

== Challenge Source Code

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/string.h>

#define MODULE_NAME "babykernel_level1.1"
#define PROC_FILENAME "pwncollege"
#define PASSWORD "lqgfblpiidjtuaho"
// In a real challenge, this might be read from a file or hidden
#define FLAG "pwn.college{recreated_flag}\n"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("pwncollege");
MODULE_DESCRIPTION("Babykernel Level 1.1 Recreated");

static struct proc_dir_entry *proc_entry;
static int authenticated = 0;

static ssize_t device_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    const char *flag_str = FLAG;
    size_t flag_len = strlen(flag_str);

    if (!authenticated)
        return -EACCES;

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

    // Check if the input starts with the password
    if (len >= pass_len && memcmp(input, PASSWORD, pass_len) == 0) {
        authenticated = 1;
        // Grant root privileges (common mechanic in pwn.college kernel challenges)
        commit_creds(prepare_kernel_cred(NULL));
        printk(KERN_INFO "babykernel: password correct, access granted\n");
    } else {
        printk(KERN_INFO "babykernel: incorrect password\n");
    }

    return len;
}

static const struct proc_ops proc_fops = {
    .proc_read = device_read,
    .proc_write = device_write,
};

static int __init babykernel_init(void)
{
    proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &proc_fops);
    if (!proc_entry) {
        printk(KERN_ALERT "babykernel: failed to create proc entry\n");
        return -ENOMEM;
    }
    printk(KERN_INFO "babykernel: module loaded\n");
    return 0;
}

static void __exit babykernel_exit(void)
{
    if (proc_entry)
        proc_remove(proc_entry);
    printk(KERN_INFO "babykernel: module unloaded\n");
}

module_init(babykernel_init);
module_exit(babykernel_exit);

```


#table(
  columns: (auto, 1fr),
  inset: 10pt,
  align: (right, left),
  [*Title*], [Basic /proc Interface Interaction],
  [*Date*], [2025-12-30],
  [*Description*], [Interacting with a custom /proc entry to trigger kernel module behavior and retrieve the flag.],
)

= Babykernel Level 1

== Introduction

This challenge introduces basic kernel-user space interaction through the `/proc` filesystem. A custom entry `/proc/pwncollege` is created by a loaded kernel module.

== Vulnerability Analysis

The kernel module implements a simple write handler for `/proc/pwncollege`. When a specific string is written to this file, the module performs an action, such as revealing the flag in the read buffer or dmesg.

== Exploitation Steps

=== 1. Writing the Secret String
By writing the required secret string to the `/proc` entry, we satisfy the module's condition.

```bash
echo -n "lxgyvowwldtjmsum" > /proc/pwncollege
```

=== 2. Retrieving the Flag
Depending on the specific variant, the flag can be read back from the same entry or found in the kernel ring buffer.

```bash
cat /proc/pwncollege
# OR
dmesg | tail
```

