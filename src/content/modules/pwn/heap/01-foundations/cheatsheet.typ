#metadata(
  (
    title: "Heap Vulnerability Cheatsheet",
    description: "Summary of common heap exploitation techniques, conditions, and targets.",
    date: "2025-12-26",
    order: 1,
  ),
)<frontmatter>

#import "../../../../../typst-theme.c.typ": project
#show: project

= Heap Vulnerability Cheatsheet

== Core Concepts

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: left,
    [*Technique*], [*Target Bin*], [*Glibc Version*],
    [Tcache Poisoning], [Tcache], [> 2.25 (Safe-linking 2.32+)],
    [Fastbin Dup], [Fastbin], [Any (requires tcache full)],
    [Unsorted Bin Attack], [Unsorted Bin], [< 2.29],
    [Unsorted Bin into Stack], [Unsorted Bin], [< 2.29],
    [Large Bin Attack], [Large Bin], [Any],
    [House of Spirit], [Fastbin/Tcache], [Any],
    [House of Lore], [Small Bin], [Any],
    [House of Force], [Top Chunk], [< 2.29],
    [Unsafe Unlink], [Small/Unsorted Bin], [Any],
    [Poison Null Byte], [Unsorted Bin], [Any],
    [Overlapping Chunks], [Any], [Any (< 2.29 for classic)],
    [House of Einherjar], [Unsorted Bin], [Any (Heap leak 2.32+)],
    [House of Water], [Tcache Metadata], [Any],
    [House of Roman], [Fastbin/Unsorted], [< 2.26 (Leakless)],
    [House of Tangerine], [Top Chunk], [Any (Modern Orange)],
    [sysmalloc \_int_free], [Top Chunk], [Any],
  ),
  caption: [Common heap exploitation techniques overview.],
)

== Techniques Detail

=== 1. Tcache Poisoning (> 2.25)
- *Condition*: UAF or Heap Overflow.
- *Mechanism*: Overwrite the `next` pointer of a freed tcache chunk.
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
- *Goal*: Write a large value (main_arena address) to an arbitrary location.

=== 4. House of Spirit
- *Condition*: Arbitrary write near a pointer that will be `free()`'d.
- *Mechanism*: Forge a fake chunk (must pass size and next-size checks) and `free()` it.
- *Goal*: Subsequent `malloc` returns the fake chunk address.

=== 5. House of Force (< 2.29)
- *Condition*: Heap Overflow into Top Chunk size.
- *Mechanism*: Overwrite Top Chunk size with `-1`.
- *Goal*: `malloc` a huge size to "wrap around" and reach any address.

=== 6. Unsafe Unlink
- *Condition*: Heap Overflow or UAF + a known pointer to the chunk.
- *Mechanism*: Forge a fake chunk with `fd` and `bk` satisfying `P->fd->bk == P` and `P->bk->fd == P`.
- *Goal*: Trigger `unlink(P)` to overwrite the pointer `P` with `&P - 3`.

=== 7. Poison Null Byte
- *Condition*: Off-by-one null byte overwrite into the next chunk's size field.
- *Mechanism*: Clear `PREV_INUSE` and set a fake `prev_size`.
- *Goal*: Trigger backward consolidation with an "in-use" chunk.

=== 8. Overlapping Chunks
- *Condition*: Overwrite the `size` field of a freed (Unsorted Bin) or in-use chunk.
- *Mechanism*: Make a chunk appear larger than it is so a subsequent allocation covers other chunks.
- *Goal*: Chunk overlap for leaks or corruption.

=== 9. House of Einherjar
- *Condition*: Off-by-one null byte overwrite + Heap Leak.
- *Mechanism*: Clear `PREV_INUSE` of next chunk and forge a `prev_size` pointing to a fake chunk.
- *Goal*: Force backward consolidation with a fake chunk (e.g., on stack).

=== 10. Large Bin Attack
- *Condition*: Overwrite `bk_nextsize` of a chunk in a Large Bin.
- *Mechanism*: Triggering insertion of a smaller chunk writes its address to `Target`.
- *Goal*: Arbitrary write of a heap address.

=== 11. House of Water
- *Condition*: UAF or Arbitrary Free.
- *Mechanism*: Abuse tcache counts to forge a size in metadata and use Small Bin refilling.
- *Goal*: Control over tcache metadata structure.

=== 12. House of Roman (< 2.26)
- *Condition*: UAF or Heap Overflow.
- *Mechanism*: Multiple partial/relative pointer overwrites (Fastbin + Unsorted Bin).
- *Goal*: Arbitrary write/hijack without leaks (requires 12-bit brute force).

=== 13. House of Tangerine (Modern)
- *Condition*: Heap Overflow / OOB into Top Chunk.
- *Mechanism*: Corrupt Top Chunk size to trigger `sysmalloc` to free it into tcache.
- *Goal*: Implicit free + tcache poisoning for arbitrary allocation.

=== 14. sysmalloc \_int_free
- *Condition*: Overwrite Top Chunk size (must be page-aligned).
- *Mechanism*: Request more than available Top Chunk to trigger `sysmalloc`.
- *Goal*: Implicit `_int_free(top_chunk)` without calling `free()`.

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
