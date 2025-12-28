#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Overview: Chunk Anatomy",
    description: "A visual overview of what allocated and freed chunks look like in different glibc bins.",
    date: "2025-12-13",
    order: 0,
    draft: true,
  ),
)<frontmatter>

= A Visual Guide to Chunks

== Introduction

Understanding the structure of a `malloc_chunk` is fundamental to heap exploitation. A chunk is a small metadata-prefixed region of memory managed by the allocator. Its structure changes depending on whether it is currently allocated (in use by the program) or free (available for a future allocation). This document provides a visual breakdown of a chunk's anatomy in both states. The detailed explanations and example source code used in this section are largely inspired by and adapted from the excellent `how2heap` repository.

The `malloc_chunk` struct in glibc is defined as:
```c
struct malloc_chunk {
  size_t      mchunk_prev_size;
  size_t      mchunk_size;
  struct malloc_chunk* fd;
  struct malloc_chunk* bk;
  struct malloc_chunk* fd_nextsize;
  struct malloc_chunk* bk_nextsize;
};
```
However, not all of these fields are used at the same time.

== Allocated Chunk

When a chunk is allocated and in use, its structure is simple. Only the size fields are considered metadata; the rest of the chunk is user-writable data.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Memory Offset*], [*Field*], [*Description*],
    [`-0x10`],
    `mchunk_prev_size`,
    [Size of the previous chunk if it is free. If previous chunk is allocated, this space is used by that chunk's user data.],

    [`-0x8`],
    `mchunk_size`,
    [Size of the current chunk. Includes metadata. The last three bits are flags (`P`, `M`, `A`). `P` (PREV_INUSE) is 1.],

    [`0x0`],
    `User Data`,
    [The pointer returned by `malloc()` points here. The program reads and writes data in this region.],

    [`...`], `...`, [`...`],
  ),
  caption: [Structure of an allocated chunk.],
)

The key takeaway is that for an in-use chunk, the memory immediately following the `mchunk_size` field is treated as user data.

== Freed Chunks

When a chunk is freed, its user data area is repurposed to store pointers (`fd`, `bk`, etc.) that link it into one of the allocator's free lists (bins). The layout depends on the type of bin the chunk is placed in.

=== T-Cache Bin (Per-Thread Cache)

The t-cache is a fast, thread-local cache for recently freed small chunks. It is a singly-linked list.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Memory Offset*], [*Field*], [*Description*],
    [`-0x8`], `mchunk_size`, [Size of the chunk.],
    [`0x0`], `next`, [Pointer to the next free chunk in this t-cache bin.],
    [`0x8`], `key`, [Pointer to the `tcache_perthread_struct` itself.],
    [`...`], `...`, [Unused space.],
  ),
  caption: [Structure of a freed chunk in a t-cache bin.],
)

=== Fastbin

Fastbins are for small chunks and also use a singly-linked list (LIFO). The check for double-frees on these chunks is simply a check against the head of the list.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Memory Offset*], [*Field*], [*Description*],
    [`-0x8`], `mchunk_size`, [Size of the chunk.],
    [`0x0`], [`fd` (Forward Pointer)], [Pointer to the next free chunk in this fastbin.],
    [`...`], `...`, [Unused space.],
  ),
  caption: [Structure of a freed chunk in a fastbin.],
)

=== Unsorted, Small, and Large Bins

These bins are used for larger chunks or as a temporary holding area (unsorted bin). They use a more robust doubly-linked list.

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Memory Offset*], [*Field*], [*Description*],
    [`-0x10`], `mchunk_prev_size`, [Size of the previous chunk.],
    [`-0x8`], `mchunk_size`, [Size of the chunk. `PREV_INUSE` bit is now 0.],
    [`0x0`], [`fd` (Forward Pointer)], [Pointer to the next chunk in the bin.],
    [`0x8`], [`bk` (Backward Pointer)], [Pointer to the previous chunk in the bin.],
    [`0x10`], [`fd_nextsize` (Large Bins only)], [Pointer to the next chunk in a different size bracket.],
    [`0x18`], [`bk_nextsize` (Large Bins only)], [Pointer to the previous chunk in a different size bracket.],
    [`...`], `...`, [Unused space.],
  ),
  caption: [Structure of a freed chunk in a doubly-linked bin.],
)

When a chunk is in one of these bins, its `PREV_INUSE` bit is cleared. The previous chunk will then use its `mchunk_prev_size` field to find the start of this free chunk during coalescing.

= Allocator Functions: A Comparison

While `malloc` is the most common function for heap allocation, `calloc` and `realloc` provide important alternative behaviors. Understanding their differences is key to both correct programming and identifying potential vulnerabilities.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Function*], [*Action*], [*Memory Content*], [*Key Behavior*],
    [`malloc(size)`], [Allocates `size` bytes.], [*Uninitialized* (garbage data)], [The simplest allocation.],
    [`calloc(n, size)`],
    [Allocates `n * size` bytes.],
    [*Zero-initialized*],
    [Guarantees memory is cleared, preventing some info leaks.],

    [`realloc(ptr, size)`],
    [Resizes block `ptr` to `size` bytes.],
    [*Preserved/Uninitialized*],
    [May move the memory block to a new location. New memory is not initialized.],
  ),
  caption: [Quick comparison of allocator functions.],
)

=== `malloc(size_t size)`
- *Action*: Allocates a single block of memory of `size` bytes.
- *Content*: The memory is *uninitialized* and can contain arbitrary data left over from previous use. This can be a source of information leaks if not handled carefully.
- *Use Case*: Standard, general-purpose memory allocation.

=== `calloc(size_t nmemb, size_t size)`
- *Action*: Allocates memory for an array of `nmemb` elements, each `size` bytes long.
- *Content*: The allocated memory is *zero-initialized*. Every byte is guaranteed to be `0`.
- *Use Case*: Useful when a zeroed block of memory is required for security or application logic. It helps prevent bugs arising from uninitialized variables.

=== `realloc(void *ptr, size_t size)`
- *Action*: Changes the size of the memory block pointed to by `ptr`.
- *Behavior*:
  - If `ptr` is `NULL`, it acts like `malloc(size)`.
  - If `size` is `0`, it acts like `free(ptr)`.
  - *Expanding*: If the new size is larger, `realloc` may try to expand the chunk in-place. If that fails, it will allocate a *new* block, copy the contents from the old block, and free the old one.
  - *Shrinking*: If the new size is smaller, the block is typically shrunk in-place.
- *Return Value*: Returns a pointer to the resized block. _This pointer may be *different* from the original `ptr`!_ If `realloc` returns `NULL`, and the original block at `ptr` is *not* freed.
- *Content*: The existing data in the block is preserved (up to the minimum of the old and new sizes). Any newly allocated memory in an expansion is *uninitialized*.
- *Security Note*: The pattern `ptr = realloc(ptr, new_size);` is dangerous. If `realloc` returns `NULL`, the original `ptr` is overwritten, leading to a memory leak.
