#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Heap Vulnerability Cheatsheet",
    description: "Summary of common heap exploitation techniques, conditions, and targets.",
    date: "2025-12-26",
    order: 5,
  ),
)<frontmatter>

= Heap Vulnerability Cheatsheet

== Core Concepts

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: left,
    [*Technique*], [*Target Bin*], [*Glibc Version*],
    [Tcache Poisoning], [Tcache], [2.27+],
    [Fastbin Dup], [Fastbin], [< 2.27 (or with Tcache full)],
    [Unsorted Bin Attack], [Unsorted Bin], [< 2.29],
    [House of Spirit], [Fastbin/Tcache], [Any (with size check)],
    [House of Lore], [Small Bin], [Any],
    [House of Force], [Top Chunk], [< 2.29],
    [Overlapping Chunks], [Any], [Any],
  ),
  caption: [Common heap exploitation techniques overview.],
)

== Techniques Detail

=== 1. Tcache Poisoning (2.27+)
- *Condition*: UAF or Heap Overflow.
- *Mechanism*: Overwrite the `next` pointer of a freed tcache chunk to an arbitrary address.
- *Goal*: Arbitrary `malloc` return.
- *Mitigation (2.32+)*: Safe-linking (pointers are XORed with `address >> 12`).

=== 2. Fastbin Dup
- *Condition*: Double Free or UAF.
- *Mechanism*: Free `A`, then `B`, then `A` again (bypass `A == head` check).
- *Goal*: Get `A` twice, allowing `next` pointer overwrite.
- *Mitigation*: Tcache must be full or disabled.

=== 3. Unsorted Bin Attack (< 2.29)
- *Condition*: Overwrite `bk` pointer of a chunk in Unsorted Bin.
- *Mechanism*: `malloc` triggers `bk->fd = unsorted_chunks(av)`.
- *Goal*: Write a large value (main_arena address) to an arbitrary location (e.g., `global_max_fast`).

=== 4. House of Spirit
- *Condition*: Arbitrary write near a pointer that will be `free()`'d.
- *Mechanism*: Forge a fake chunk (must pass size checks) and pass its address to `free()`.
- *Goal*: Subsequent `malloc` returns the fake chunk address.

=== 5. House of Force (< 2.29)
- *Condition*: Heap Overflow into Top Chunk size.
- *Mechanism*: Overwrite Top Chunk size with `-1` (0xffffffffffffffff).
- *Goal*: `malloc` a huge size to "wrap around" the memory space and reach any address.

== Useful Glibc Offsets

- `__free_hook` (gone in 2.34+)
- `__malloc_hook` (gone in 2.34+)
- `main_arena` (found via offset from Libc base)
- `global_max_fast` (used in unsorted bin attacks)

== Debugging Commands (pwndbg)

```bash
heap        # Show heap summary
bins        # Show all bins (tcache, fast, unsorted, small, large)
tcache      # Show tcache content
fastbins    # Show fastbins
vis         # Visualise heap chunks
mp          # Show malloc_par (metadata like global_max_fast)
```
