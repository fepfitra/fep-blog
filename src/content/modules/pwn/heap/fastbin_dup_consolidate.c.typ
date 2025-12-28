#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Fastbin Dup with malloc_consolidate",
    description: "Leveraging malloc_consolidate and a double free to duplicate a pointer to a tcache-sized chunk.",
    date: "2025-12-13",
    order: 22,
  ),
)<frontmatter>

= glibc Allocator: Fastbin Dup with `malloc_consolidate`

== Introduction

This document demonstrates an advanced heap exploitation technique that combines a double-free with the internal `malloc_consolidate` function. This method allows an attacker to gain two pointers to the same chunk, even for sizes that are normally protected against simple double-frees (like t-cache sized chunks).

The core idea is to have a pointer to a small fastbin chunk, trigger `malloc_consolidate` via a large allocation so that the large allocation starts at the same address as the small chunk, and then use the old pointer to free the new large chunk, achieving a type of use-after-free.

== Prerequisites
- *T-cache Exhaustion*: Ability to fill the t-cache for a small size to ensure the chunk is placed in the fastbin.
- *Pointer Aliasing*: A vulnerability that allows the attacker to maintain a pointer to a chunk that is subsequently merged and re-allocated as part of a larger chunk.
- *Consolidation Trigger*: Ability to request an allocation larger than `0x400` bytes to trigger the `malloc_consolidate` function.

== `malloc_consolidate` Explained

`malloc_consolidate` is an internal glibc function that merges all chunks currently in the fastbins back into the main bins. It is triggered in specific situations, most notably for our purposes when a *large chunk* is requested and there are no suitable chunks in the small or large bins. This forces the allocator to tidy up the fastbins before looking at the top chunk.

== Example from `fastbin_dup_consolidate.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/*
Original reference: https://valsamaras.medium.com/the-toddlers-introduction-to-heap-exploitation-fastbin-dup-consolidate-part-4-2-ce6d68136aa8

This document is mostly used to demonstrate malloc_consolidate and how it can be leveraged with a
double free to gain two pointers to the same large-sized chunk, which is usually difficult to do
directly due to the previnuse check. Interestingly this also includes tcache-sized chunks of certain sizes.

malloc_consolidate(https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4714)
essentially
merges all fastbin chunks with their neighbors, puts them in the unsorted bin and merges them with top
if possible.

As of glibc version 2.35 it is called only in the following five places:
1. _int_malloc: A large sized chunk is being allocated (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3965)
2. _int_malloc: No bins were found for a chunk and top is too small (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4394)
3. _int_free: If the chunk size is >= FASTBIN_CONSOLIDATION_THRESHOLD (65536) (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4674)
4. mtrim: Always (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5041)
5. __libc_mallopt: Always (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5463)

We will be targeting the first place, so we will need to allocate a chunk that does not belong in the
small bin (since we are trying to get into the 'else' branch of this check: https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3901).
This means our chunk will need to be of size >= 0x400 (it is thus large-sized). Notably, the
biggest tcache sized chunk is 0x410, so if our chunk is in the [0x400, 0x410] range we can utilize
a double free to gain control of a tcache sized chunk.
*/

#define CHUNK_SIZE 0x400

int main() {
	printf("This technique will make use of malloc_consolidate and a double free to gain a duplication in the tcache.\n");
	printf("Lets prepare to fill up the tcache in order to force fastbin usage...\n\n");

	void *ptr[7];

	for(int i = 0; i < 7; i++)
		ptr[i] = malloc(0x40);

	void* p1 = malloc(0x40);
	printf("Allocate another chunk of the same size p1=%p \n", p1);

	printf("Fill up the tcache...\n");
	for(int i = 0; i < 7; i++)
		free(ptr[i]);

  	printf("Now freeing p1 will add it to the fastbin.\n\n");
  	free(p1);

	printf("To trigger malloc_consolidate we need to allocate a chunk with large chunk size (>= 0x400)\n");
	printf("which corresponds to request size >= 0x3f0. We will request 0x400 bytes, which will gives us\n");
	printf("a tcache-sized chunk with chunk size 0x410 ");
  	void* p2 = malloc(CHUNK_SIZE);

	printf("p2=%p.\n", p2);

	printf("\nFirst, malloc_consolidate will merge the fast chunk p1 with top.\n");
	printf("Then, p2 is allocated from top since there is no free chunk bigger (or equal) than it. Thus, p1 = p2.\n");

	assert(p1 == p2);

  	printf("We will double free p1, which now points to the 0x410 chunk we just allocated (p2).\n\n");
	free(p1); // vulnerability (double free)
	printf("It is now in the tcache (or merged with top if we had initially chosen a chunk size > 0x410).\n");

	printf("So p1 is double freed, and p2 hasn't been freed although it now points to a free chunk.\n");

	printf("We will request 0x400 bytes. This will give us the 0x410 chunk that's currently in\n");
	printf("the tcache bin. p2 and p1 will still be pointing to it.\n");
	void *p3 = malloc(CHUNK_SIZE);

	assert(p3 == p2);

	printf("We now have two pointers (p2 and p3) that haven't been directly freed\n");
	printf("and both point to the same tcache sized chunk. p2=%p p3=%p\n", p2, p3);
	printf("We have achieved duplication!\n\n");

	printf("Note: This duplication would have also worked with a larger chunk size, the chunks would\n");
	printf("have behaved the same, just being taken from the top instead of from the tcache bin.\n");
	printf("This is pretty cool because it is usually difficult to duplicate large sized chunks\n");
	printf("because they are resistant to direct double free's due to their PREV_INUSE check.\n");

	return 0;
}
```

== Attack Flow Explained

=== 1. Setup: Place a Chunk in the Fastbin

First, we need a chunk in a fastbin. As in previous examples, we achieve this by filling the corresponding t-cache bin first.

```c
// Fill tcache for size 0x50 (request 0x40)
for(int i = 0; i < 7; i++) free(ptr[i]);
// Free p1, which now goes to the fastbin
free(p1);
```
#figure(
  table(
    columns: (auto, auto),
    inset: 10pt,
    align: center,
    [*Bin*], [*State*],
    [T-Cache (0x50)], "[FULL]",
    [Fastbin (0x50)], "[ `p1` ]",
  ),
  caption: [State before consolidation: `p1` is in the fastbin.],
)

=== 2. Trigger `malloc_consolidate`

Next, we trigger the consolidation by requesting a large chunk. This forces the allocator to process the fastbins.

```c
void* p2 = malloc(CHUNK_SIZE); // CHUNK_SIZE = 0x400
```
During this call, `malloc_consolidate` is invoked. It sees `p1` in the fastbin, removes it, and merges it with the top chunk. Immediately after, the allocator serves the `0x400`-byte request from the newly-sized top chunk. The result is that the new chunk, `p2`, starts at the *exact same address* as the old `p1`.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Pointer*], [*Address*], [*Note*],
    [`p1`], `0xADDR`, [Points to a (now-defunct) `0x50` chunk],
    [`p2`], `0xADDR`, [Points to a new, valid `0x410` chunk],
  ),
  caption: [Pointer Aliasing: After consolidation, both `p1` and `p2` point to the same memory address, but conceptually represent different chunks.],
)
The `assert(p1 == p2)` passes, confirming this.

=== 3. The "Double" Free

Now we have two pointers to the same address. We can use the old pointer, `p1`, to free the *new, larger chunk* pointed to by `p2`.

```c
free(p1); // Effectively free(p2)
```
Since the chunk size is `0x410`, which is within the t-cache range, the chunk is placed at the head of the `0x410` t-cache bin. Crucially, we still have the pointer `p2`, which now points to a freed chunk.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Bin*], [*State*], [*Held Pointer*],
    [T-Cache (0x410)], "[ `p2` ]", [`p2` (dangling)],
  ),
  caption: [The `0x410` chunk is in the t-cache, but we still have a pointer to it.],
)


=== 4. Final Duplication

The final step is to allocate another chunk of the same size. The allocator will serve it from the t-cache.

```c
void *p3 = malloc(CHUNK_SIZE);
assert(p3 == p2);
```
The allocator returns the chunk at the head of the `0x410` t-cache bin, which is the one at address `p2`. The `assert` passes, and we have successfully obtained two valid pointers (`p2` and `p3`) to the same writable memory region.

This technique is powerful because it bypasses the `PREV_INUSE` check that protects non-fastbin chunks from direct double-frees, by creating a situation where we have an old, aliased pointer (`p1`) that we can use to free a new, larger chunk (`p2`).

