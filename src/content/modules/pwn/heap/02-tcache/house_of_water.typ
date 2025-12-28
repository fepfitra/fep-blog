#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Water",
    description: "A complex technique to achieve tcache metadata control by leveraging overlapping tcache counts and small bin reverse refilling.",
    date: "2025-12-26",
    order: 14,
  ),
)<frontmatter>

= glibc Allocator: House of Water

== Introduction

The *House of Water* is an advanced heap exploitation technique that converts a Use-After-Free (UAF) or arbitrary-free primitive into *tcache metadata control*. By controlling the tcache metadata, an attacker can hijack any subsequent tcache-sized allocation and potentially leak libc pointers.

The core idea relies on several clever observations:
1. *Tcache Counts as Metadata*: The tcache metadata structure starts with a series of 2-byte counts for each bin. By freeing chunks of specific large sizes (e.g., `0x3e0` and `0x3f0`), the attacker can set specific count bytes to `0x01`, effectively forging a `size` field (like `0x10001`) inside the tcache metadata.
2. *Tcache Bins as Pointers*: The tcache bin headers (the actual linked list heads) follow the counts. The forged `size` field can be positioned such that it appears to be the header of a very large chunk that overlaps with these bin headers.
3. *Small Bin Reverse Refilling*: When the tcache is empty and a `malloc` request is satisfied by the Small Bin, glibc attempts to "refill" the tcache by moving all other chunks from that Small Bin into the tcache. By corrupting the Small Bin's doubly-linked list (`fd`/`bk`) to include the tcache metadata, the attacker can trick this refilling logic into placing the tcache metadata itself into a tcache bin.

== Prerequisites
- *UAF / Arbitrary-Free*: Ability to free a pointer that is still in use, or free an arbitrary address.
- *Small Bin Corruption*: Ability to overwrite `fd`/`bk` pointers of chunks in the Small Bin.
- *Size Control*: Ability to allocate and free specific large chunks (e.g., `0x3e0`, `0x3f0`) to manipulate tcache metadata counts.
- *Metadata Layout*: Ability to satisfy "next chunk" integrity checks at specific offsets (e.g., forging a fake header at `metadata + 0x10000`).

== Example Code

This PoC demonstrates how to obtain a pointer to the tcache metadata as a returned chunk from `malloc`.

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

int main(void) {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	// 1. Forge size header in tcache metadata
	void *fake_size_lsb = malloc(0x3d8);
	void *fake_size_msb = malloc(0x3e8);
	free(fake_size_lsb);
	free(fake_size_msb);

	void *metadata = (void *)((long)(fake_size_lsb) & ~(0xfff));

	// 2. Prepare Small Bin chunks
	void *x[7];
	for (int i = 0; i < 7; i++) x[i] = malloc(0x88);

	void *small_start = malloc(0x88);
	malloc(0x18); 
	void *small_middle = malloc(0x88);
	malloc(0x18); 
	void *small_end = malloc(0x88);
	malloc(0x18); 

	// 3. Satisfy Next Chunk checks
	malloc(0xf000); 
	void *end_of_fake = malloc(0x18);
	*(long *)end_of_fake = 0x10000;
	*(long *)(end_of_fake+0x8) = 0x20;

	for (int i = 0; i < 7; i++) free(x[i]);

	// 4. Overlay Small Bin pointers with Tcache headers (simulated UAF)
	*(long*)(small_start-0x18) = 0x31;
	free(small_start-0x10);
	*(long*)(small_start-0x8) = 0x91; 

	*(long*)(small_end-0x18) = 0x21;
	free(small_end-0x10);
	*(long*)(small_end-0x8) = 0x91; 

	free(small_end);
	free(small_middle);
	free(small_start);

	// 5. VULNERABILITY: Corrupt Small Bin list to include metadata
	*(unsigned long *)small_start = (unsigned long)(metadata+0x80);
	*(unsigned long *)(small_end+0x8) = (unsigned long)(metadata+0x80);

	for(int i=0; i<9; i++) malloc(0x88); // Cash out

	void *meta_chunk = malloc(0x88);
	assert(meta_chunk == (metadata+0x90));
	return 0;
}
```

== Attack Flow Explained

=== 1. Forging the 0x10001 Header

The tcache metadata begins with a `counts` array (one byte or `uint16_t` per bin). By freeing chunks of size `0x3e0` and `0x3f0`, we set the counts for those bins to `1`. In memory, this sets bytes that the allocator, if tricked, will interpret as a `size` field (e.g., `0x00010001`).

=== 2. The Padding and Next-Chunk Check

Because we've forged a massive size (`0x10000`), when the allocator tries to `free` or `malloc` this fake chunk, it will check the metadata of the "next" chunk located at `header + 0x10000`. We must allocate and write sane metadata at that specific offset to pass the integrity checks.

=== 3. Small Bin Corruption

We prepare a Small Bin with three chunks. We then use a separate primitive to point the `0x20` and `0x30` tcache bins to the headers of our Small Bin chunks. Finally, we use a vulnerability to overwrite the `bk` of the first Small Bin chunk and the `fd` of the last Small Bin chunk to point to the *tcache metadata* itself.

=== 4. Reverse Refilling

When `malloc(0x88)` is called and the `0x90` tcache bin is empty, glibc looks in the Small Bin. It finds `small_start`, returns it to the user, and then *moves all other chunks in that bin into the tcache*.

Since we've linked the tcache metadata into the Small Bin, the refilling logic will:
1. Take the "next" chunk in the Small Bin (our metadata).
2. Place it into the tcache.
3. Continue until the Small Bin is empty.

A subsequent `malloc(0x88)` will now return a pointer that points directly into the tcache metadata.

== Impact

Once an attacker controls the tcache metadata, they can:
- *Hijack any bin*: Overwrite any tcache bin header to point to an arbitrary address.
- *Leak pointers*: The tcache metadata often contains residual libc and heap pointers.
- *Bypass Safe-Linking*: Since the attacker can write to the metadata directly, they can set the pointers to their desired values without needing to worry about the XOR-masking logic used in `fd` pointers.
