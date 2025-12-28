#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "T-Cache Index Calculation",
    description: "An explanation of how the t-cache index is calculated in glibc's memory allocator.",
    date: "2025-12-13",
    order: 18,
  ),
)<frontmatter>

= T-Cache Index Calculation

== Introduction

The glibc malloc implementation uses a t-cache (thread-local cache) for small allocations to improve performance. This document explains how the t-cache index is calculated for a given allocation size, based on the example code in `calc_tcache_idx.c`.

== Prerequisites
- *GLIBC Version*: The t-cache was introduced in glibc 2.26. This calculation is relevant for all versions from 2.26 onwards.

== Example from `calc_tcache_idx.c`

The `calc_tcache_idx.c` code provides a utility to determine the t-cache bin index for a requested allocation size (`malloc(x)`).

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>


struct malloc_chunk {

  size_t      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  size_t      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

/* The corresponding word size.  */
#define SIZE_SZ (sizeof (size_t))

#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
			  ? __alignof__ (long double) : 2 * SIZE_SZ)

/* The corresponding bit mask value.  */
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)

/* The smallest possible chunk */
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))

/* The smallest size we can malloc is an aligned minimal chunk */
#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)

/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

int main()
{
    unsigned long long req;
    unsigned long long tidx;

    while(scanf("%llx", &req) != EOF) {
        tidx = usize2tidx(req);
        printf("TCache Idx: %llu\n", tidx);
    }
    return 0;
}
```

== Formula Explained

The core of the calculation is the `usize2tidx` macro, which translates a user-requested size into a t-cache index.

1. *request2size*: First, the requested size is converted to the actual chunk size that will be allocated. This includes space for metadata and ensures proper alignment.
2. *csize2tidx*: Then, the resulting chunk size is used to calculate the t-cache index.

The formula is essentially:
```
IDX = (CHUNK_SIZE - MIN_CHUNK_SIZE) / MALLOC_ALIGNMENT
```

This ensures that each t-cache bin corresponds to a specific range of chunk sizes. The interactive program allows you to input a size and see the resulting t-cache index, which is useful for understanding heap layout and preparing for heap exploitation challenges.

== Example T-Cache Indices

Here is a table showing the t-cache index for different allocation sizes on a 64-bit system.

#figure(
  table(
    columns: 4,
    [*Requested Size (Hex)*], [*Requested Size (Decimal)*], [*Chunk Size (Hex)*], [*T-Cache Index*],
    [`0x1` - `0x18`], "1 - 24", `0x20`, "0",
    [`0x19` - `0x28`], "25 - 40", `0x30`, "1",
    [`0x29` - `0x38`], "41 - 56", `0x40`, "2",
    [`0x39` - `0x48`], "57 - 72", `0x50`, "3",
    "...", "...", "...", "...",
    [`0x3F9` - `0x408`], "1017 - 1032", `0x410`, "63",
  ),
  caption: [Example T-Cache index calculations for a 64-bit system.],
)