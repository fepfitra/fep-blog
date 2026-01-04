#metadata(
  (
    title: "Cross-Arch Syscall Confusion",
    description: "Writeup for Sandboxing Level 9",
    date: "2026-01-01",
    order: 9,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Cross-Arch Syscall Confusion

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

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);

    int shellcode_size = read(0, shellcode, 0x1000);

    scmp_filter_ctx ctx;

    ctx = seccomp_init(SCMP_ACT_ALLOW);
    for (int i = 0; i < 512; i++)
    {
        switch (i)
        {
        case SCMP_SYS(close):
            continue;
        case SCMP_SYS(stat):
            continue;
        case SCMP_SYS(fstat):
            continue;
        case SCMP_SYS(lstat):
            continue;
        }
        assert(seccomp_rule_add(ctx, SCMP_ACT_KILL, i, 0) == 0);
    }

    seccomp_arch_add(ctx, SCMP_ARCH_X86);

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

= Cross-Arch Syscall Confusion

Level 9 uses a Seccomp filter that whitelists only four syscalls: `close`, `stat`, `fstat`, and `lstat`. Crucially, it also enables support for the 32-bit architecture (`SCMP_ARCH_X86`).

Seccomp filters work by checking the syscall number. However, syscall numbers are different between 64-bit and 32-bit architectures.

*Syscall Mapping:*
- 64-bit: 3 = `close`, 4 = `stat`
- 32-bit: 3 = `read`, 4 = `write`

Because the filter whitelists syscall numbers 3 and 4 (thinking they are `close` and `stat` in 64-bit), we can use the 32-bit syscall entry point (`int 0x80`) to call `read` and `write` instead.

*Exploit Strategy:*
1. Call 32-bit `open` (5)? Wait, 5 is whitelisted?
  - 64-bit 5 is `fstat`.
  - 32-bit 5 is `open`.
2. So we can use 32-bit syscall 5 to open the flag.
3. Use 32-bit syscall 3 to read the flag.
4. Use 32-bit syscall 4 to write the flag to stdout.

This is a powerful bypass that occurs when a sandbox allows multiple architectures but doesn't properly validate syscall numbers against the architecture used during the call.
