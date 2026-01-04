#metadata(
  (
    title: "Classic Chroot Escape",
    description: "Using the classic double-chroot technique to escape a jail when the chroot syscall is allowed within the sandbox.",
    date: "2025-12-30",
    order: 7,
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
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chroot), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

= Classic Chroot Escape

== Introduction

This level allows the `chroot` and `chdir` syscalls inside the jail, enabling the classic escape technique.

== Vulnerability Analysis

If a process inside a `chroot` jail is allowed to call `chroot` again, it can escape. By creating a subdirectory, `chrooting` into it, and then calling `chdir("..")` multiple times, the process can move its CWD past the current root and into the host's real filesystem.

== Exploitation Steps

=== 1. Nested Chroot
1. `mkdir("escape")`
2. `chroot("escape")`

=== 2. Climbing Out
Now that the root is at `escape`, but the CWD is also at `escape`, we can `chdir("..")`. This moves the CWD to the *old* root. Since we are already at the "root" according to the current `chroot` context, another `chdir("..")` will move the CWD *outside* the jail on many kernel versions, or we can repeat this many times.

```nasm
/* chdir("../../../..") */
lea rdi, [rip + dotdot_str]
mov rax, 80 /* SYS_chdir */
syscall
```

=== 3. Final Escape
Once outside, call `chroot(".")` to set the new root to the real host root.
