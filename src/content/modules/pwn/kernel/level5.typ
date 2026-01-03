#metadata(
  (
    title: "Kernel Level 5",
    description: "Writeup for Kernel Level 5",
    date: "2026-01-01",
    order: 5,
    draft: true,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project



#table(
  columns: (auto, 1fr),
  inset: 10pt,
  align: (right, left),
  [*Title*], [Kernel Privilege Elevation via ioctl],
  [*Date*], [2025-12-30],
  [*Description*],
  [Triggering a privilege elevation function ('win') within a kernel module using the ioctl system call.],
)

= Babykernel Level 5

== Introduction

This challenge demonstrates how user-space programs can interact with kernel modules using `ioctl` to trigger specific internal functions.

== Vulnerability Analysis

The kernel module defines a `device_ioctl` handler that responds to a specific request code (`0x539`). When this code is received, it calls an internal `win` function. The `win` function typically uses `commit_creds(prepare_kernel_cred(0))` to elevate the calling process's privileges to root.

== Exploitation Steps

=== 1. Opening the Device
The program opens the character device or proc entry associated with the module.

```c
int fd = open("/proc/pwncollege", O_RDWR);
```

=== 2. Triggering the Win Function
By calling `ioctl` with the correct request code, the `win` function is executed in kernel mode.

```c
ioctl(fd, 0x539, 0);
```

=== 3. Spawning a Root Shell
Once the kernel has elevated our privileges, we can call `system("/bin/sh")` to get a root shell.

```c
system("/bin/sh");
```

