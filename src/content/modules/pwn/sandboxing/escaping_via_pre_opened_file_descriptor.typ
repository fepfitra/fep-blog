#metadata(
  (
    title: "Escaping via Pre-opened File Descriptor",
    description: "Writeup for Sandboxing Level 2",
    date: "2026-01-01",
    order: 2,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Escaping via Pre-opened File Descriptor

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

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    assert(argc > 1);

    // Checking to make sure you're not trying to open the flag.
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    assert(chroot(jail_path) == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);

    int shellcode_size = read(0, shellcode, 0x1000);

    ((void(*)())shellcode)();
}
```

== Escaping via Pre-opened File Descriptor

This challenge opens a file specified in `argv[1]` *before* it initializes the jail. This file descriptor remains open and valid even after the `chroot()` call.

By passing `/` as the argument, we get a file descriptor pointing to the real root directory of the host system. Once the program enters the jail and executes our custom shellcode, we can use `openat()` to open files relative to this pre-opened file descriptor.

*Vulnerability:*
```c
int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
// ... mkdtemp, chroot, etc ...
((void(*)())shellcode)();
```

*Shellcode Logic:*
1. Use `openat(3, "flag", O_RDONLY)` to open the real flag. (The leaked FD is usually 3).
2. `read()` the flag into a buffer.
3. `write()` the buffer to stdout.

*Exploit Command:*
```bash
python3 exploit.py
```
This script passes `/` to the binary, then sends shellcode that uses FD 3 to read `/flag`.
