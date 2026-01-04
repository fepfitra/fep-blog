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
#define _GNU_SOURCE 1

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
#include <time.h>
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

== Chroot without chdir

In this challenge, the program calls `chroot()` into a temporary directory but fails to call `chdir("/")` immediately after. This is a common mistake when implementing jails.

The `chroot()` syscall changes the root directory for the calling process and its future children, but it does *not* change the current working directory (CWD). If the process is at `/home/user` and calls `chroot("/tmp/jail")`, its root becomes `/tmp/jail`, but its CWD is still effectively at the original `/home/user/any/directory`.

Since we are outside the new root, we can use relative paths to traverse upwards and reach the real root of the filesystem.

*Exploit:*
```bash
./challenge ../../../flag
```
The program opens the file relative to the CWD, which is still outside the jail, allowing us to read the real flag.

== Testing Locally

To run this binary on a standard Linux system without root privileges (and without `sudo`), you can use *User Namespaces*. The `unshare` command allows you to create a new namespace where you have the `CAP_SYS_CHROOT` capability.

```bash
unshare -r ./challenge ../../../flag
```

The `-r` flag (or `--map-root-user`) maps your current user to the root user inside the new namespace, permitting the `chroot()` syscall to succeed.

=== Simulating the Challenge Environment
In real CTF environments, the challenge binary is typically owned by `root` and has the *SUID bit* set. This allows it to call `chroot()` even when run by a normal user.

If you have `sudo` access and want to simulate this exact setup locally:

```bash
echo "well done baby" | sudo tee /flag
gcc -o challenge c.c
sudo chown root:root ./challenge
sudo chmod u+s ./challenge
./challenge ../../../flag  # Now it works without sudo!
```

Without `sudo`, the `unshare -r` method remains the best way to test the vulnerability. Standard file permissions (`chmod 777`) only control who can run the binary, not what kernel capabilities (like `CAP_SYS_CHROOT`) the process has once it's running.
