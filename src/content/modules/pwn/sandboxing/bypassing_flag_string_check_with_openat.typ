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

= Bypassing flag-string check with openat

== Introduction

This level adds a check to prevent opening any file whose name contains the string "flag" before entering the jail. However, we can still open the root directory `/`.

== Vulnerability Analysis

The program checks `argv[1]` for the "flag" substring but allows us to open other paths.

```c
assert(strstr(argv[1], "flag") == NULL);
int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
```

By passing `/` as `argv[1]`, we get a file descriptor pointing to the real root directory. The seccomp filter then restricts us to a few syscalls, including `openat`.

== Exploitation Steps

=== 1. Leaking the Root FD
Pass `/` as the first argument to the program. This opens the host's root directory and assigns it a file descriptor (usually 3).

=== 2. Using openat
In the shellcode, use the `openat` syscall with the leaked file descriptor to open "flag".

```nasm
/* openat(3, "flag", O_RDONLY) */
mov rdi, 3
lea rsi, [rip + flag_str]
mov rdx, 0
mov rax, 257 /* SYS_openat */
syscall
```

=== 3. Reading the Flag
Use `sendfile` or `read`/`write` to output the contents of the opened flag file to stdout.
