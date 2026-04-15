---
title: "Fastbin Dup with malloc_consolidate"
description: "Leveraging malloc_consolidate and a double free to duplicate a pointer to a tcache-sized chunk."
date: "2025-12-13"
order: 22
---

# glibc Allocator: Fastbin Dup with `malloc_consolidate`

## Introduction

This document demonstrates an advanced heap exploitation technique that combines a double-free with the internal `malloc_consolidate` function. This method allows an attacker to gain two pointers to the same chunk, even for sizes that are normally protected against simple double-frees (like t-cache sized chunks).

The core idea is to have a pointer to a small fastbin chunk, trigger `malloc_consolidate` via a large allocation so that the large allocation starts at the same address as the small chunk, and then use the old pointer to free the new large chunk, achieving a type of use-after-free.

## Prerequisites
- **T-cache Exhaustion**: Ability to fill the t-cache for a small size to ensure the chunk is placed in the fastbin.
- **Pointer Aliasing**: A vulnerability that allows the attacker to maintain a pointer to a chunk that is subsequently merged and re-allocated as part of a larger chunk.
- **Consolidation Trigger**: Ability to request an allocation larger than `0x400` bytes to trigger the `malloc_consolidate` function.

## `malloc_consolidate` Explained

`malloc_consolidate` is an internal glibc function that merges all chunks currently in the fastbins back into the main bins. It is triggered in specific situations, most notably for our purposes when a **large chunk** is requested and there are no suitable chunks in the small or large bins. This forces the allocator to tidy up the fastbins before looking at the top chunk.

## Example from `fastbin_dup_consolidate.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define CHUNK_SIZE 0x400

int main() {
	void *ptr[7];

	for(int i = 0; i < 7; i++)
		ptr[i] = malloc(0x40);

	void* p1 = malloc(0x40);

	for(int i = 0; i < 7; i++)
		free(ptr[i]);

  	free(p1);

	// Trigger malloc_consolidate
  	void* p2 = malloc(CHUNK_SIZE);

	assert(p1 == p2);

  	free(p1); // VULNERABILITY: Double Free

	void *p3 = malloc(CHUNK_SIZE);

	assert(p3 == p2);
	return 0;
}
```

## Attack Flow Explained

### 1. Setup: Place a Chunk in the Fastbin

First, we need a chunk in a fastbin. As in previous examples, we achieve this by filling the corresponding t-cache bin first.

```c
// Fill tcache for size 0x50 (request 0x40)
for(int i = 0; i < 7; i++) free(ptr[i]);
// Free p1, which now goes to the fastbin
free(p1);
```
| Bin | State |
| --- | --- |
| T-Cache (0x50) | FULL |
| Fastbin (0x50) | `p1` |

**State before consolidation: `p1` is in the fastbin.**

### 2. Trigger `malloc_consolidate`

Next, we trigger the consolidation by requesting a large chunk. This forces the allocator to process the fastbins.

```c
void* p2 = malloc(CHUNK_SIZE); // CHUNK_SIZE = 0x400
```
During this call, `malloc_consolidate` is invoked. It sees `p1` in the fastbin, removes it, and merges it with the top chunk. Immediately after, the allocator serves the `0x400`-byte request from the newly-sized top chunk. The result is that the new chunk, `p2`, starts at the **exact same address** as the old `p1`.

| Pointer | Address | Note |
| --- | --- | --- |
| `p1` | `0xADDR` | Points to a (now-defunct) `0x50` chunk |
| `p2` | `0xADDR` | Points to a new, valid `0x410` chunk |

**Pointer Aliasing: After consolidation, both `p1` and `p2` point to the same memory address, but conceptually represent different chunks.**
The `assert(p1 == p2)` passes, confirming this.

### 3. The "Double" Free

Now we have two pointers to the same address. We can use the old pointer, `p1`, to free the **new, larger chunk** pointed to by `p2`.

```c
free(p1); // Effectively free(p2)
```
Since the chunk size is `0x410`, which is within the t-cache range, the chunk is placed at the head of the `0x410` t-cache bin. Crucially, we still have the pointer `p2`, which now points to a freed chunk.

| Bin | State | Held Pointer |
| --- | --- | --- |
| T-Cache (0x410) | `p2` | `p2` (dangling) |

**The `0x410` chunk is in the t-cache, but we still have a pointer to it.**


### 4. Final Duplication

The final step is to allocate another chunk of the same size. The allocator will serve it from the t-cache.

```c
void *p3 = malloc(CHUNK_SIZE);
assert(p3 == p2);
```
The allocator returns the chunk at the head of the `0x410` t-cache bin, which is the one at address `p2`. The `assert` passes, and we have successfully obtained two valid pointers (`p2` and `p3`) to the same writable memory region.

This technique is powerful because it bypasses the `PREV_INUSE` check that protects non-fastbin chunks from direct double-frees, by creating a situation where we have an old, aliased pointer (`p1`) that we can use to free a new, larger chunk (`p2`).
