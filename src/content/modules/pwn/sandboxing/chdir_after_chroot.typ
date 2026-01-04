#metadata(
  (
    title: "Chdir(\"/") after chroot",
    description: "Writeup for Sandboxing Level 3",
    date: "2026-01-01",
    order: 3,
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

    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);

    int shellcode_size = read(0, shellcode, 0x1000);

    ((void(*)())shellcode)();
}
```

== Chdir("/") after chroot

Level 3 correctly calls `chdir("/")` after `chroot()`, ensuring that the current working directory is moved inside the jail. However, the vulnerability from Level 2 persists: a file descriptor opened before the jail was initialized remains accessible to the shellcode.

Even though we are now inside the jail and our CWD is at the jail's root, we still have a handle (FD 3) to the real root directory outside.

*Exploit:*
The strategy is identical to Level 2. We provide `/` as the first argument and use `openat(3, "flag", ...)` in our shellcode to reach the real flag.

```
