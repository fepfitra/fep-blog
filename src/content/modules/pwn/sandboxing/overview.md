---
title: "Sandboxing Overview"
description: "Introduction to Linux sandboxing techniques including chroot, seccomp, and namespaces, and how to test them locally."
date: "2026-01-04"
order: 0
draft: false
---

# Sandboxing Overview

Sandboxing is the practice of isolating a process from the rest of the system to limit the potential damage if the process is compromised. In Linux, this is typically achieved using a combination of technologies.

## Common Techniques

### Chroot
`chroot` (change root) changes the apparent root directory for the current running process and its children. A program running in a chroot environment cannot name (and therefore normally cannot access) files outside the designated directory tree.

### Seccomp (Secure Computing Mode)
Seccomp is a kernel feature that restricts the system calls a process can make. It is often used to whitelist only the necessary syscalls (like `read`, `write`, `exit`) and block dangerous ones (like `execve`, `fork`, `socket`).

### Namespaces
Namespaces allow isolating global system resources. Common namespaces include:
- **Mount (mnt):** Isolates filesystem mount points.
- **Process ID (pid):** Isolates the process ID number space.
- **Network (net):** Isolates network interfaces.
- **User (user):** Isolates user and group IDs.

# Syscalls and Shellcode

System calls (syscalls) are the interface between a user-space program and the Linux kernel. When you want to read a file, open a network connection, or exit a program, you use a syscall.

In binary exploitation (pwn), particularly in sandboxed environments, we often inject **shellcode**—raw machine code instructions—to execute syscalls directly.

## How Syscalls Work (x86-64)

To invoke a syscall in x86-64 assembly:
1. Load the **syscall number** into the `rax` register.
2. Load arguments into `rdi`, `rsi`, `rdx`, `r10`, `r8`, and `r9`.
3. Execute the `syscall` instruction.

### Example: `exit(0)`
- Syscall number for `exit` is 60.
- Argument 1 (status code) is 0.

```nasm
mov rax, 60       ; syscall number for exit
xor rdi, rdi      ; status = 0
syscall           ; invoke kernel
```

### Example: `write(1, "Hello", 5)`
- Syscall number for `write` is 1.
- Arg 1 (fd) = 1 (stdout).
- Arg 2 (buf) = address of string.
- Arg 3 (count) = 5.

```nasm
mov rax, 1
mov rdi, 1
lea rsi, [rip + hello_str]
mov rdx, 5
syscall
```

## Common Syscalls Used in Payloads

The following system calls are frequently used in the exploits throughout this module. Knowing their syscall numbers is essential for writing custom shellcode.

| Name | Number (x64) | Common Usage |
| --- | --- | --- |
| `read` | `0` | Read data from a file descriptor into a buffer. |
| `write` | `1` | Write data from a buffer to a file descriptor. |
| `open` | `2` | Open a file and return a file descriptor. |
| `nanosleep` | `35` | Pause execution for a specified duration (timing leaks). |
| `sendfile` | `40` | Copy data between file descriptors (bypass read/write blocks). |
| `exit` | `60` | Terminate the process (leak data via exit code). |
| `chdir` | `80` | Change the current working directory. |
| `fchdir` | `81` | Change CWD to a directory referenced by an FD (jail escape). |
| `mkdir` | `83` | Create a new directory. |
| `chroot` | `161` | Change the root directory. |
| `openat` | `257` | Open a file relative to a directory FD (jail escape). |
| `linkat` | `265` | Create a hard link relative to directory FDs. |

## Shellcraft: Automated Shellcode Generation

While writing assembly manually gives you fine-grained control, it can be tedious and error-prone. Fortunately, `pwntools` includes a powerful tool called **Shellcraft**. It provides a library of pre-written assembly snippets for common system calls and tasks.

Instead of manually loading registers and triggering interrupts, you can generate shellcode using simple Python function calls:

```python
# Generate assembly for openat(3, "flag", O_RDONLY)
sc = shellcraft.openat(3, "flag", 0)

# Generate assembly for sendfile(1, rax, 0, 100)
# (assuming rax contains the FD from the previous call)
sc += shellcraft.sendfile(1, 'rax', 0, 100)

# Assemble into raw bytes
payload = asm(sc)
```

This module heavily utilizes `shellcraft` in the exploit scripts to keep them concise and readable.

### Note on Architecture Confusion
In [Cross-Arch Syscall Confusion](/modules/pwn/sandboxing/9_cross_arch_syscall_confusion), we exploit the overlap between 64-bit and 32-bit syscall numbers. For reference, the 32-bit (x86) numbers used were:
- `read`: 3 (corresponds to x64 `close`)
- `write`: 4 (corresponds to x64 `stat`)
- `open`: 5 (corresponds to x64 `fstat`)

# Testing Sandboxes Locally

To run this binary on a standard Linux system without root privileges (and without `sudo`), you can use **User Namespaces**. The `unshare` command allows you to create a new namespace where you have the `CAP_SYS_CHROOT` capability.

```bash
unshare -r ./challenge ../../../../..//flag
```

The `-r` flag (or `--map-root-user`) maps your current user to the root user inside the new namespace, permitting the `chroot()` syscall to succeed.

## Simulating the Challenge Environment
In real CTF environments, the challenge binary is typically owned by `root` and has the **SUID bit** set. This allows it to call `chroot()` even when run by a normal user.

If you have `sudo` access and want to simulate this exact setup locally:

```bash
echo "well done baby" | sudo tee /flag
gcc -o challenge c.c
sudo chown root:root ./challenge
sudo chmod u+s ./challenge
./challenge ../../../flag  # Now it works without sudo!
```

Without `sudo`, the `unshare -r` method remains the best way to test the vulnerability. Standard file permissions (`chmod 777`) only control who can run the binary, not what kernel capabilities (like `CAP_SYS_CHROOT`) the process has once it's running.
