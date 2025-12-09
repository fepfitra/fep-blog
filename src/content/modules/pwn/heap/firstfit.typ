#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "glibc Allocator: First-Fit Algorithm",
    description: "An explanation of the first-fit algorithm used by glibc's memory allocator.",
    date: "2025-12-09",
    order: 17,
  ),
)<frontmatter>
= glibc Allocator: First-Fit Algorithm

== Introduction

The glibc malloc implementation uses a first-fit algorithm for selecting free chunks of memory. This document explains how this algorithm works, based on the example code in `first_fit.c`.

== The First-Fit Algorithm

When a request for memory is made (e.g., via `malloc`), the allocator searches for a suitable free chunk. The first-fit algorithm works as follows:

1. The allocator maintains lists of free chunks of different sizes.
2. When a new allocation is requested, the allocator starts searching from the beginning of the list of free chunks.
3. The first chunk that is large enough to satisfy the allocation request is chosen.
4. If the chosen chunk is larger than the requested size, it is split into two parts:
  *   One part is returned to the user.
  *   The other part remains free and is placed back into the appropriate free list.

== Example from `first_fit.c`

The `first_fit.c` code provides a practical demonstration of this algorithm.

=== Step 1: Initial Allocations

Two buffers, `a` and `b`, are allocated:

```c
char* a = malloc(0x512);
char* b = malloc(0x256);
```

The allocator places these chunks in memory, one after the other.

=== Step 2: Freeing a Chunk

The first buffer, `a`, is freed:

```c
free(a);
```

This places the chunk of size `0x512` back into a free list.

=== Step 3: Re-allocating a Smaller Chunk

A new, smaller buffer, `c`, is allocated:

```c
c = malloc(0x500);
```

Because the allocator uses a first-fit strategy, it finds the recently freed chunk (originally `a`) is the first one large enough to hold `0x500` bytes.

=== Step 4: The Result

The new allocation, `c`, is placed at the same memory address that `a` previously occupied. This is because the `0x512` byte chunk was the first free chunk large enough to satisfy the `0x500` byte request.

The original content of `a` is overwritten by the new content of `c`. This demonstrates that a reference to `a` after `free(a)` is a "use-after-free" vulnerability.

== Security Implications

The first-fit algorithm can have security implications, particularly in use-after-free scenarios. If an attacker can control the size of allocations after a vulnerable object has been freed, they may be able to reclaim that memory region with an object of their own, potentially leading to code execution.
