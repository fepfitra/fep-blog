#metadata(
  (
    title: "Sandboxing Level 1",
    description: "Writeup for Sandboxing Level 1",
    date: "2026-01-01",
    order: 1,
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

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");
    puts("The only thing you can do in this challenge is read out one single file, as specified by the first argument to the");
    puts("program (argv[1]).\n");

    assert(argc > 1);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    printf("Sending the file at `%s` to stdout.\n", argv[1]);
    sendfile(1, open(argv[1], 0), 0, 128);

}
```



== Level 1: chroot without chdir

In this challenge, the program calls `chroot()` into a temporary directory but fails to call `chdir("/")` immediately after. This is a common mistake when implementing jails.

The `chroot()` syscall changes the root directory for the calling process and its future children, but it does *not* change the current working directory (CWD). If the process is at `/home/user` and calls `chroot("/tmp/jail")`, its root becomes `/tmp/jail`, but its CWD is still effectively at the original `/home/user`.

Since we are outside the new root, we can use relative paths to traverse upwards and reach the real root of the filesystem.

*Exploit:*
```bash
/challenge/babyjail_level1 ../../../flag
```
The program opens the file relative to the CWD, which is still outside the jail, allowing us to read the real flag.

