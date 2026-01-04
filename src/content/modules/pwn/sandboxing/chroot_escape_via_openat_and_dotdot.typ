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
    write(fffd, "FLAG{FAKE}", 10);
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

= Chroot Escape via openat and ..

== Introduction

This challenge provides limited syscalls: `openat`, `read`, `write`, and `sendfile`.

== Vulnerability Analysis

While no directory FD is explicitly leaked in this level, we can use `openat(AT_FDCWD, "..", ...)` to attempt traversal. In some configurations or if an FD was accidentally left open, `openat` can be used to escape.

However, the primary intent of this level is often to demonstrate that without a handle to the outside world, escaping `chroot` is difficult even with `openat`. If the challenge intended an escape, it might rely on more advanced kernel interactions or a subtle logic error.

== Exploitation Steps

In a typical pwn.college scenario for this level, the process might be vulnerable to a race condition or an unlinked file access if other interactions are possible. Given the allowed syscalls, we primarily target any files reachable via path traversal.
