#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Tcache Stashing Unlink Attack",
    description: "Exploiting the tcache stashing mechanism in the small bin to gain an arbitrary allocation and create a fake chunk.",
    date: "2025-12-28",
    order: 50,
  ),
)<frontmatter>

= Tcache Stashing Unlink Attack

== Introduction

The "Tcache Stashing Unlink" is a sophisticated heap exploitation technique that targets the way glibc (specifically from 2.27 onwards) refills the tcache from the Small Bins. When a `malloc` request is satisfied by a Small Bin chunk and the corresponding tcache bin has empty slots, glibc "stashes" the remaining chunks from that Small Bin into the tcache.

By corrupting the `bk` pointer of a chunk in the Small Bin, an attacker can trick this stashing logic into linking an arbitrary memory location (like the stack or a global variable) into the tcache.

== Prerequisites
- *Small Bin Control*: Ability to place chunks into the Small Bin (requires bypassing/filling tcache and triggering consolidation/sorting).
- *BK Overwrite*: A vulnerability (like a heap overflow) to overwrite the `bk` pointer of a chunk in the Small Bin.
- *Writable Address*: A known writable address to satisfy the `bck->fd = bin` check in glibc's `unlink` macro (or rather the stashing logic's equivalent).
- *Calloc/Malloc Pair*: Often `calloc` is used to trigger the Small Bin allocation because it bypasses the tcache for its initial allocation.

== Example from `tcache_stashing_unlink.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(){
    unsigned long stack_var[0x10] = {0};
    unsigned long *chunk_lis[0x10] = {0};
    unsigned long *target;

    setbuf(stdout, NULL);

    // Set up fake chunk bk to bypass checks
    stack_var[3] = (unsigned long)(&stack_var[2]);

    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    // Fill tcache
    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    free(chunk_lis[1]);
    
    // Put chunks into unsorted bin
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    // Move to small bin
    malloc(0xa0);

    // Leave space in tcache
    malloc(0x90);
    malloc(0x90);

    // VULNERABILITY: Corrupt small bin bk
    chunk_lis[2][1] = (unsigned long)stack_var;

    // Trigger stashing unlink
    calloc(1,0x90);

    target = malloc(0x90);   

    assert(target == &stack_var[2]);
    return 0;
}
```

== Attack Flow Explained

=== 1. Tcache and Small Bin Preparation

To use Small Bins, the tcache for the target size must first be partially filled. In the example, we free 7 chunks to fill the tcache, then free more chunks which go into the *Unsorted Bin*. By allocating a larger size, these chunks are sorted into the *Small Bin*.

We then allocate some chunks from the tcache to leave at least two slots open.

=== 2. Corrupting the Small Bin BK

The vulnerability is used to overwrite the `bk` pointer of a chunk currently in the Small Bin. We point it to our fake chunk location (the stack).

```c
chunk_lis[2][1] = (unsigned long)stack_var;
```

=== 3. Triggering the Stashing Refill

We call `calloc(1, 0x90)`. `calloc` does not use chunks directly from the tcache. It looks in the Small Bin, finds a chunk, and returns it. Crucially, it then sees that the tcache for size `0x90` has empty slots and begins "stashing" the rest of the chunks from that Small Bin into the tcache.

The stashing logic follows the corrupted `bk` chain:
1. It takes the next chunk (`chunk_lis[0]`).
2. It follows its `bk` to our `stack_var`.
3. It "stashes" our `stack_var` into the tcache.

=== 4. Arbitrary Allocation

The next `malloc(0x90)` request will be served directly from the tcache, returning the pointer to our stack variable.

== Security Implications

This attack is particularly dangerous because it bypasses many tcache protections and can be used to link non-heap memory into the heap management structures. It also results in a pointer to the arena being written to the fake chunk's `bk->fd` location, which can sometimes be used as an information leak.