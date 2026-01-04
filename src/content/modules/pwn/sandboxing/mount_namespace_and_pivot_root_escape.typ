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
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    assert(execl("/bin/bash", "/bin/bash", "-p", NULL) != -1);
}

```

= Mount Namespace and pivot_root Escape

== Introduction

This challenge uses more advanced Linux isolation features: **Mount Namespaces** and `pivot_root`. These are the building blocks of modern containerization (like Docker).

== Vulnerability Analysis

The program performs the following steps to create the jail:
1. Creates a new mount namespace using `unshare(CLONE_NEWNS)`.
2. Creates a new temporary directory to serve as the new root.
3. Uses `pivot_root` to move the current root to a subdirectory (`/old`) and set the new temporary directory as the root.
4. Bind-mounts essential directories (`/bin`, `/usr`, `/lib`, `/lib64`) from `/old` into the new root.

The critical vulnerability is that the **old root remains mounted at `/old`** and is never unmounted.

```c
    puts("... pivoting the root filesystem!");
    assert(syscall(SYS_pivot_root, new_root, old_root) != -1);
    ...
    // let's remove the old root mount
```

Despite the comment, there is no code to `umount("/old")`. Therefore, the entire host filesystem is still accessible from within the jail under the `/old` prefix.

== Exploitation Steps

=== 1. Accessing the Flag
Once the shell is spawned inside the jail, we can simply read the real flag by prefixing the path with `/old`.

```bash
cat /old/flag
```

The program's "fake" flag is at `/flag` (relative to the new root), but the real flag remains at its original location on the host, now reachable via `/old/flag`.
