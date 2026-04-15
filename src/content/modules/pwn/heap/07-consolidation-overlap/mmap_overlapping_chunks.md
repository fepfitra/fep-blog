---
title: "mmap Overlapping Chunks"
description: "Exploiting large mmap-allocated chunks by corrupting their size to trigger overlapping munmap/mmap sequences."
date: "2025-12-26"
order: 64
---

# glibc Allocator: mmap Overlapping Chunks

## Introduction

In glibc, when an allocation request exceeds a certain size (defined by the `mmap_threshold`), the allocator bypasses the main heap and uses the `mmap` system call to create a separate memory mapping for that specific chunk. These "mmap chunks" behave differently from standard heap chunks:

1. **Allocation**: They are created via `mmap` and are typically located between the main heap and the libraries (libc, ld) in the process's virtual memory space.
2. **Metadata**: The `IS_MMAPPED` bit (the second least significant bit of the `size` field) is set to 1.
3. **Deallocation**: When `free()` is called on an mmap chunk, the allocator uses the `munmap` system call to release the memory directly back to the kernel.

The "mmap Overlapping Chunks" attack involves corrupting the `size` field of an mmap chunk so that when it is freed, the `munmap` call releases a larger region of memory than intended, potentially including other active mmap chunks. If the attacker then performs a new large allocation, the kernel may reuse the released memory range, leading to multiple pointers pointing to overlapping mmap regions.

## Prerequisites
- **Mmap Allocation**: Ability to trigger large allocations (typically > 128KB) that use the `mmap` syscall instead of the main heap.
- **Metadata Corruption**: Ability to overwrite the `size` field of an mmap-allocated chunk.
- **Allocation/Reclamation Control**: Ability to trigger a subsequent large `malloc` to reclaim the released virtual memory range.

## Example from `mmap_overlapping_chunks.c`

This PoC demonstrates the attack by corrupting the size of one large chunk to encompass another, triggering an overlap after a re-allocation.

```c
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

int main()
{
	malloc(0x10);

	long long* top_ptr = malloc(0x100000);
	long long* mmap_chunk_2 = malloc(0x100000);
	long long* mmap_chunk_3 = malloc(0x100000);

	// VULNERABILITY: Corrupt mmap size to overlap chunks
	mmap_chunk_3[-1] = (0xFFFFFFFFFD & mmap_chunk_3[-1]) + (0xFFFFFFFFFD & mmap_chunk_2[-1]) | 2;

	// Munmaps both regions
	free(mmap_chunk_3);

	// Reclaim released virtual memory
	long long* overlapping_chunk = malloc(0x300000);

	int distance = mmap_chunk_2 - overlapping_chunk;
	overlapping_chunk[distance] = 0x1122334455667788;

	assert(mmap_chunk_2[0] == overlapping_chunk[distance]);
	return 0;
}
```

## Attack Flow Explained

### 1. Mmap Allocation Behavior

When the program requests `0x100000` bytes, glibc sees this is above the `mmap_threshold` and calls `mmap`. Successive mmap calls typically result in chunks being allocated at decreasing addresses (moving "down" towards the heap).

| Chunk | Approx. Address | Metadata Size |
| --- | --- | --- |
| `mmap_chunk_2` | `0x7f...a000` | `0x100000 | 2` |
| `mmap_chunk_3` | `0x7f...9000` | `0x100000 | 2` |

**Simplified view of mmap chunks in memory.**

### 2. The Vulnerability: Size Corruption

By overwriting `mmap_chunk_3->size` with the combined size of `mmap_chunk_3` and `mmap_chunk_2`, we trick the allocator into thinking `mmap_chunk_3` is a single `0x200000` byte mapping.

### 3. Arbitrary Munmap

When `free(mmap_chunk_3)` is called, glibc reads the corrupted size and calls `munmap(mmap_chunk_3 - offset, 0x200000)`. Because mmap chunks are adjacent (or nearly adjacent), this releases the memory for **both** chunks to the kernel.

**Note**: Unlike normal heap chunks, once an mmap region is munmapped, accessing the original pointers (`mmap_chunk_2`) will cause a Segmentation Fault because the memory is no longer mapped in the process's address space.

### 4. Re-mapping and Overlap

To complete the attack, we must reclaim that memory. We call `malloc(0x300000)`. The kernel is likely to reuse the largest available hole in the virtual memory space, which is the region we just released.

The new `overlapping_chunk` pointer now covers the entire range. An attacker who still holds the "stale" `mmap_chunk_2` pointer can now interact with the memory through two different pointers, or if `mmap_chunk_2` was a pointer in a different part of the application, we have achieved a cross-allocation overlap.

| State | Pointer | Memory Range |
| --- | --- | --- |
| Stale | `mmap_chunk_2` | 0x100000 bytes at original location |
| New | `overlapping_chunk` | 0x300000 bytes encompassing the above |

**The new allocation overlaps the old, supposedly freed, chunk location.**
