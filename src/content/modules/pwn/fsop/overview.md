---
title: "Overview"
description: "Resources and write-ups on File Stream Oriented Programming."
date: "2026-01-01"
order: 2
---

# Overview: A Visual Guide to File Stream Oriented Programming (FSOP)

"File Stream Oriented Programming (FSOP) is an advanced binary exploitation technique that leverages the internal structures of the C standard library's stream handling (Glibc `FILE` structures). By corrupting these objects, attackers can bypass modern mitigations like DEP and ASLR, turning limited memory corruption vulnerabilities into powerful arbitrary read, write, or code execution primitives."

This module is based on the research presented in the whitepaper [FILE Structures: Another Binary Exploitation Technique](https://gsec.hitb.org/materials/sg2018/WHITEPAPERS/FILE%2520Structures%2520-%2520Another%2520Binary%2520Exploitation%2520Technique%2520-%2520An-Jie%2520Yang.pdf) by An-Jie Yang.

## Introduction

Memory corruption vulnerabilities like buffer overflows have long been targets for exploitation. While mitigations like DEP (Data Execution Prevention), ASLR (Address Space Layout Randomization), and RELRO (Relocation Read-Only) have made exploitation harder, attackers have evolved techniques like ROP (Return-Oriented Programming).

FSOP targets the `FILE` structure in the GNU C Library (Glibc). By forging `FILE` structures and their associated virtual function tables, attackers can hijack control flow during standard file operations like `fopen`, `fread`, or `fclose`.

## Background

### File Stream

In C, a file stream is a logical interface to various devices (disk, screen, keyboard). When standard I/O functions are used, the kernel handles data via a buffer to reduce system calls. Glibc implements this with `FILE` structures.

### FILE Structure

The `FILE` structure (internally `struct _IO_FILE`) is the backbone of Glibc stream I/O. Below is a simplified representation of its key members used in exploitation:

```c
struct _IO_FILE
{
  int _flags;          /* Magic number and status flags */

  /* Stream buffer pointers */
  char *_IO_read_ptr;   /* Current read pointer */
  char *_IO_read_end;   /* End of read area */
  char *_IO_read_base;  /* Start of read area */
  char *_IO_write_base; /* Start of write area */
  char *_IO_write_ptr;  /* Current write pointer */
  char *_IO_write_end;  /* End of write area */
  char *_IO_buf_base;   /* Start of reserve area */
  char *_IO_buf_end;    /* End of reserve area */

  struct _IO_marker *_markers;
  struct _IO_FILE *_chain; /* Linked list of all open files */
  int _fileno;             /* File descriptor */
  int _flags2;
  __off64_t _offset;
  _IO_lock_t *_lock;       /* Lock used for thread safety */
  /* ... (other fields) */
  struct _IO_wide_data *_wide_data; /* Wide character stream data */
  /* ... (other fields) */
};

struct _IO_FILE_plus
{
  struct _IO_FILE file;
  const struct _IO_jump_t *vtable; /* Virtual function table */
};

/* Extra data for wide character streams. */
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;

  wchar_t _shortbuf[1];

  const struct _IO_jump_t *_wide_vtable;
};
```

The `_IO_wide_data` structure mirrors the buffer management pointers found in `_IO_FILE` but specifically for wide characters (`wchar_t`). Most importantly for exploitation, it includes its own vtable pointer (`_wide_vtable`), which is often targeted in advanced FSOP techniques when the main `FILE` vtable is protected.

#### Flags and Magic Numbers

The `_flags` field is a bitmask where the high 16 bits are reserved for a magic number (`_IO_MAGIC`), and the low 16 bits contain the actual status flags.

```c
/* Magic number and bits for the _flags field. */
#define _IO_MAGIC         0xFBAD0000 /* Magic number */
#define _IO_MAGIC_MASK    0xFFFF0000
#define _IO_USER_BUF          0x0001 /* Don't deallocate buffer on close. */
#define _IO_UNBUFFERED        0x0002
#define _IO_NO_READS          0x0004 /* Reading not allowed.  */
#define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
#define _IO_EOF_SEEN          0x0010
#define _IO_ERR_SEEN          0x0020
#define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close.  */
#define _IO_LINKED            0x0080 /* In the list of all open files.  */
#define _IO_IN_BACKUP         0x0100
#define _IO_LINE_BUF          0x0200
#define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
#define _IO_CURRENTLY_PUTTING 0x0800
#define _IO_IS_APPENDING      0x1000
#define _IO_IS_FILEBUF        0x2000
#define _IO_USER_LOCK         0x8000
```

#### Structure Offsets (x86-64)

| Offset | Field | Description |
| --- | --- | --- |
| `0x00` | `_flags` | Status flags and magic number |
| `0x08` | `_IO_read_ptr` | Current read pointer |
| `0x10` | `_IO_read_end` | End of read area |
| `0x18` | `_IO_read_base` | Start of read area |
| `0x20` | `_IO_write_base` | Start of write area |
| `0x28` | `_IO_write_ptr` | Current write pointer |
| `0x30` | `_IO_write_end` | End of write area |
| `0x38` | `_IO_buf_base` | Start of reserve area |
| `0x40` | `_IO_buf_end` | End of reserve area |
| ... | `_IO_save_base, _IO_backup_base, _IO_save_end, _markers` | Not important |
| `0x68` | `_chain` | Next FILE struct in the list |
| `0x70` | `_fileno` | File descriptor |
| ... | `_old_offset, _cur_column, _vtable_offset. _shortbuf` | Not important |
| `0x88` | `_lock` | Pointer to lock object |
| ... | `_offset, _codecvt` | Not important |
| `0xA0` | `_wide_data` | Pointer to wide data struct |
| ... | `_freeres_list, _freeres_buf, pad5, _mode, _unused2` | Not important |
| `0xD8` | `vtable` | Virtual function table pointer |

#### Structure Offsets: `_IO_wide_data` (x86-64)

| Offset | Field | Description |
| --- | --- | --- |
| `0x00` | `_IO_read_ptr` | Current read pointer |
| `0x18` | `_IO_write_base` | Start of write area |
| `0x20` | `_IO_write_ptr` | Current put pointer |
| `0x30` | `_IO_buf_base` | Start of reserve area |
| `0x38` | `_IO_buf_end` | End of reserve area |
| ... | `_IO_save_base, _IO_backup_base, _IO_save_end, _IO_state, _IO_last_state, _codecvt, _shortbuf` | Not important |
| `0xE0` | `_wide_vtable` | Virtual function table for wide characters |

Key elements for exploitation include:

- **`_flags`**: A bitmask encoding the stream's state. It contains a "magic" upper half (`0xFBADxxxx`) and status flags in the lower half. These flags dictate critical behavior:
  - **Permissions**: `_IO_NO_READS` (`0x0004`) and `_IO_NO_WRITES` (`0x0008`) control whether reading or writing is allowed.
  - **Buffering**: `_IO_UNBUFFERED` (`0x0002`) and `_IO_LINE_BUF` (`0x0200`) determine how data is cached.
  - **Exploitation**: Sometimes, attackers manipulate these bits to satisfy internal Glibc checks.
- **Stream Buffers**:
  - Read buffer: `_IO_read_ptr`, `_IO_read_end`, `_IO_read_base`
  - Write buffer: `_IO_write_ptr`, `_IO_write_end`, `_IO_write_base`
  - Reserve buffer: `_IO_buf_base`, `_IO_buf_end`
- `_fileno`: The underlying file descriptor (0 for stdin, 1 for stdout, 2 for stderr).
- `_IO_file_plus`: An extension containing the **virtual function table (vtable)** pointer.

All file operations go through this vtable. Additionally, all `FILE` structures are linked in a global list via `_IO_list_all` and the `_chain` pointer.

### The Global FILE List (\_IO_list_all)

Glibc maintains a global linked list of all active `FILE` structures. The head of this list is a global variable called `_IO_list_all`. Each `FILE` structure has a `_chain` member (at offset `0x68`) that points to the next `FILE` structure in the list.

When a new file is opened (e.g., via `fopen`), it is added to the head of the list. The chain traversal follows the `_chain` pointers:

setaso

$$
"_IO_list_all" arrow.r "opened file" arrow.r "stdin" arrow.r "stdout" arrow.r "NULL"
$$

**The `_IO_list_all` chain linking file structures via their `_chain` members.**

This list is traversed by the internal function `_IO_flush_all_lockp`, which is called during normal program termination (`exit`), when `main` returns, or when `abort` is invoked.

#### The `_IO_flush_all_lockp` Mechanism

This function iterates through the `_IO_list_all` chain and attempts to flush every stream. To trigger an exploit (like an arbitrary leak or code execution) during this traversal, we must satisfy specific conditions within our corrupted `FILE` structure to reach the `overflow` call.

```c
// Simplified glibc/libio/genops.c
int _IO_flush_all_lockp (int do_lock) {
  struct _IO_FILE *fp = (_IO_ITER) _IO_list_all;
  while (fp != NULL) {
    // Condition to trigger a flush (and thus call the overflow vtable entry)
    if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
         || (fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)))) {

      // The target call: calls the function at vtable + 0x18 (for _IO_new_file_overflow)
      if (_IO_OVERFLOW (fp, EOF) == EOF)
        result = EOF;
    }
    fp = fp->_chain;
  }
}
```

**Important Note on Chaining**: The traversal relies on `fp->_chain` to find the next stream. If an attacker corrupts a `FILE` structure such that its `_chain` pointer is invalid (e.g., points to unmapped memory), the loop will crash (Segfault) before processing subsequent streams. Conversely, setting `_chain` to `NULL` will gracefully terminate the loop. This behavior is critical when chaining multiple exploits or ensuring stability.

To exploit this, an attacker often overwrites `_IO_list_all` to point to a fake `FILE` structure. By setting `_IO_write_ptr > _IO_write_base` and `_mode <= 0`, they force the program to call `_IO_OVERFLOW`, which can be hijacked if the vtable is also corrupted.

### Examining file stream in GDB

Try compile any program and incpect the `stdin` pointer in GDB, we can observe the populated fields of the `_IO_FILE` structure:

```bash
(gdb) p _IO_2_1_stdin_
```
```c
$1 = {
  file = {
    _flags = -72540021,
    _IO_read_ptr = 0x7ffff7e08963 <_IO_2_1_stdin_+131> "",
    _IO_read_end = 0x7ffff7e08963 <_IO_2_1_stdin_+131> "",
    _IO_read_base = 0x7ffff7e08963 <_IO_2_1_stdin_+131> "",
    _IO_write_base = 0x7ffff7e08963 <_IO_2_1_stdin_+131> "",
    _IO_write_ptr = 0x7ffff7e08963 <_IO_2_1_stdin_+131> "",
    _IO_write_end = 0x7ffff7e08963 <_IO_2_1_stdin_+131> "",
    _IO_buf_base = 0x7ffff7e08963 <_IO_2_1_stdin_+131> "",
    _IO_buf_end = 0x7ffff7e08964 <_IO_2_1_stdin_+132> "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x0,
    _fileno = 0,
    _flags2 = 0,
    _short_backupbuf = "",
    _old_offset = -1,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x7ffff7e0a7a0 <_IO_stdfile_0_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x7ffff7e089c0 <_IO_wide_data_0>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    _prevchain = 0x7ffff7e09628 <_IO_2_1_stdout_+104>,
    _mode = 0,
    _unused3 = 0,
    _total_written = 0,
    _unused2 = "\000\000\000\000\000\000\000"
  },
  vtable = 0x7ffff7e07030
}
```

The GDB output above reveals the internal state of `stdin` during runtime. This structure is technically `_IO_FILE_plus`, which wraps the standard `_IO_FILE` (seen as the `file` member) and appends the `vtable`.

Understanding these fields is crucial for crafting FSOP exploits:

- **`file._flags`**: The value `-72540021` (hex: `0xfb9b808b`) contains `_IO_MAGIC` (top 2 bytes) and various status flags. In many exploits, modifying these flags (e.g., clearing `_IO_NO_WRITES`) is a prerequisite for triggering specific code paths.
- **Buffer Pointers**: Notice that `_IO_read_ptr`, `_IO_read_end`, and `_IO_buf_base` all point to the same region. This indicates the buffer state. By corrupting these pointers, we can redirect I/O operations to arbitrary memory locations (Arbitrary Read/Write).
- **`file._fileno`**: Set to `0`, which is the standard file descriptor for `stdin`. For `stdout`, this would be `1`.
- **`file._lock`**: Points to `_IO_stdfile_0_lock`. Glibc uses this for thread safety. Many FSOP gadgets (like those in `fclose`) will crash if this pointer doesn't point to a **writable area of memory**.
- **`vtable`**: Explicitly shown at the end (`0x7ffff7e07030 <_IO_file_jumps>`). This pointer determines which functions are called for operations like `fread`, `fwrite`, or `close`. Redirecting this pointer is the core of execution hijacking.

## Exploitation of FILE Structure

### Code Execution via Vtable Hijacking

The most direct attack involves overwriting the vtable pointer. If an attacker controls the `FILE` structure (e.g., on the heap or in BSS), they can point the vtable to a fake table they control. When a file function is called, the program executes the attacker's gadgets.

To successfully hijack the flow during `fclose`, one must often satisfy constraints, such as ensuring `_lock` points to writable memory.

### File-Stream Oriented Programming (FSOP)

FSOP chains `FILE` structures to control flow repeatedly, similar to ROP. The target is often `_IO_flush_all_lockp`, a function called during `abort`, `exit`, or when `main` returns. This function iterates through `_IO_list_all`.

By overwriting `_IO_list_all`, an attacker can inject a fake `FILE` chain. As the cleanup function processes each link, it calls virtual functions on the attacker's fake structures, granting code execution.

### Vtable Verification

Since Glibc 2.24, vtable verification checks if the vtable pointer falls within the valid `_IO_vtable` section (specifically `__libc_IO_vtables`). This mitigates direct vtable hijacking unless the attacker can point the vtable to a valid entry within this section that offers useful primitives.

This module covers `_IO_wfile_jumps`. It uses the `_wide_data` structure (which has its own vtable, often unchecked or exploitable via `_IO_wfile_overflow`) to hijack control flow.
