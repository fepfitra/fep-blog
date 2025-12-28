#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "First-Fit Algorithm",
    description: "An explanation of the first-fit algorithm used by glibc's memory allocator.",
    date: "2025-12-09",
    order: 2,
  ),
)<frontmatter>

= glibc Allocator: First-Fit Algorithm

== Introduction

The glibc malloc implementation uses a first-fit algorithm for selecting free chunks of memory. This document explains how this algorithm works, based on the example code in `first_fit.c`.

=== Visualization

Let's visualize the memory state at different stages of the first-fit algorithm.

== Example from `first_fit.c`

The `first_fit.c` code provides a practical demonstration of this algorithm.

=== Step 1: Initial Allocations

Two buffers, `a` and `b`, are allocated:

```c
char* a = malloc(0x512);
char* b = malloc(0x256);
```

#figure(
  table(
    columns: (auto, auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Address*], [*Size*], [*Status*], [*Chunk*],
    "0x00", "0x512", [*Allocated*], [a],
    "0x512", "0x256", [*Allocated*], [b],
    "0x768", "...", [*Free*], "...",
  ),
  caption: [Initial State: After `a` and `b` are allocated.],
)

The allocator places these chunks in memory, one after the other.

=== Step 2: Freeing a Chunk

The first buffer, `a`, is freed:

```c
free(a);
```

This places the chunk of size `0x512` back into a free list.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Address*], [*Size*], [*Status*], [*Chunk*],
    "0x00", "0x512", [*Free*], [a (freed)],
    "0x512", "0x256", [*Allocated*], "b",
    "0x768", "...", [*Free*], "...",
  ),
  caption: [State after `free(a)`.],
)

=== Step 3: Re-allocating a Smaller Chunk

A new, smaller buffer, `c`, is allocated:

```c
c = malloc(0x500);
```

Because the allocator uses a first-fit strategy, it finds the recently freed chunk (originally `a`) is the first one large enough to hold `0x500` bytes.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Address*], [*Size*], [*Status*], [*Chunk*],
    "0x00", "0x500", [*Allocated*], [c],
    "0x500", "0x12", [*Free*], "remainder of a",
    "0x512", "0x256", [*Allocated*], "b",
    "0x768", "...", [*Free*], "...",
  ),
  caption: [State after `c = malloc(0x500)`.],
)

=== Step 4: The Result

The new allocation, `c`, is placed at the same memory address that `a` previously occupied. This is because the `0x512` byte chunk was the first free chunk large enough to satisfy the `0x500` byte request.

The original content of `a` is overwritten by the new content of `c`. This demonstrates that a reference to `a` after `free(a)` is a "use-after-free" vulnerability.

== Security Implications

The first-fit algorithm can have security implications, particularly in use-after-free scenarios. If an attacker can control the size of allocations after a vulnerable object has been freed, they may be able to reclaim that memory region with an object of their own, potentially leading to code execution.

== Prerequisites
- *Use-After-Free (UAF)*: The application must maintain a reference to a memory region after it has been `free()`-d.
- *Allocation Control*: Ability to trigger a new `malloc()` of a size that is equal to or smaller than the freed chunk, allowing the attacker to reclaim the memory.

== Example from `first_fit.c`
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	char* a = malloc(0x512);
	char* b = malloc(0x256);
	char* c;

	strcpy(a, "this is A!");

	free(a);

	c = malloc(0x500);
	strcpy(c, "this is C!");

	return 0;
}
```
