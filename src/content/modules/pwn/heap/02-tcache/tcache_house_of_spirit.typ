#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Tcache House of Spirit",
    description: "A variation of House of Spirit that targets the tcache, which has fewer integrity checks than fastbins.",
    date: "2025-12-28",
    order: 11,
  ),
)<frontmatter>

= Tcache House of Spirit

== Introduction

The "Tcache House of Spirit" is a modernized version of the House of Spirit attack. It leverages the Thread Local Cache (tcache) introduced in glibc 2.26. Like the original attack, it tricks `free()` into adding a fake chunk (located in non-heap memory like the stack) into a freelist.

However, the tcache implementation in glibc is optimized for speed and lacks many of the integrity checks present in the fastbin or other bins. Specifically, `_int_free` calls `tcache_put` without verifying if the "next chunk" is valid. This makes the attack simpler to execute as fewer fake metadata fields need to be crafted.

== Prerequisites
- *Known Target Address*: The attacker needs to know the address of the memory region they want to allocate.
- *Write Primitive*: Ability to write a fake `size` field to the target memory region.
- *Free Primitive*: Ability to pass the pointer of the fake chunk to `free()`.
- *Alignment*: The pointer passed to `free()` must be 16-byte aligned on 64-bit systems.

== Example from `tcache_house_of_spirit.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	malloc(1);

	unsigned long long *a; 
	unsigned long long fake_chunks[10] __attribute__((aligned(0x10))); 

	// Craft fake chunk size
	fake_chunks[1] = 0x40; 

	// Overwrite pointer to point to fake chunk region
	a = &fake_chunks[2];

	free(a);

	void *b = malloc(0x30);

	assert((long)b == (long)&fake_chunks[2]);
}
```

== Attack Flow Explained

=== 1. Preparation

Unlike the fastbin version, we don't necessarily need to fill the tcache unless it's already full for that size. In this example, we assume the tcache is empty or has space.

=== 2. Craft the Fake Chunk

We only need to set the `size` field of the fake chunk.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Index*], [*Address*], [*Content*], [*Note*],
    [`fake_chunks[1]`], `&fake_chunks[1]`, [`0x40`], [Fake chunk *size* field.],
    [`fake_chunks[2]`], `&fake_chunks[2]`, `...`, [Start of user data. `a` points here.],
  ),
  caption: [Simplified fake chunk layout for tcache.],
)

The "next chunk" check that exists for fastbins is skipped by tcache.

=== 3. Freeing the Fake Chunk

When `free(a)` is called, glibc checks if the chunk fits in the tcache. Since `0x40` is a tcache-sized chunk, it is placed directly into the tcache list without checking the surrounding memory.

=== 4. Allocation

The subsequent `malloc(0x30)` call finds the fake chunk at the head of the tcache and returns it.

== Comparison with Fastbin House of Spirit

| Feature | Fastbin House of Spirit | Tcache House of Spirit |
| :--- | :--- | :--- |
| **Next Chunk Size Check** | Required (must be sane) | **Not required** |
| **Tcache State** | Must be full | Must have space |
| **Speed/Simplicity** | Moderate | High |
| **Glibc Version** | Any | 2.26+ |

