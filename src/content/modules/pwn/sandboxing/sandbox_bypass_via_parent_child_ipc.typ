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

= Sandbox Bypass via Parent-Child IPC

== Introduction

This challenge implements a multi-process sandbox. The parent process forks a child, which is then heavily restricted using seccomp (only `read`, `write`, and `exit` are allowed). However, the parent and child maintain a communication channel via a `socketpair`.

== Vulnerability Analysis

The parent process acts as a request handler for the child. It waits for 128-byte commands over the socket and performs actions based on the command name:
1. `print_msg`: Prints the provided argument to stdout.
2. `read_file`: Opens a specified file and sends its contents back to the child using `sendfile`.

The vulnerability is that the parent does not validate the file path requested by the `read_file` command. The child, although restricted from calling `open` directly, can ask the parent to open and read `/flag` on its behalf.

== Exploitation Steps

=== 1. Requesting the Flag
The child process sends a `read_file` command to the parent over the socket (FD 4).

```nasm
/* write(4, "read_file\0/flag\0", 128) */
```

=== 2. Receiving the Data
The child then reads the response from the socket. Since the parent uses `sendfile`, the contents of `/flag` are now in the child's memory.

```nasm
/* read(4, buffer, 128) */
```

=== 3. Exfiltrating the Flag
To output the flag, the child sends a `print_msg` command back to the parent, with the flag content as the argument. The parent, running outside the sandbox, prints it to the real stdout.

```nasm
/* write(4, "print_msg\0" + flag_content, 128) */
```

The retrieved flag was: `falg`.
