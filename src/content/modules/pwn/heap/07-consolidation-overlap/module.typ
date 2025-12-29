#metadata(
  (
    title: "Consolidation & Overlap",
    description: "Abusing the allocator's merging logic to create overlapping chunks and cross-allocation control.",
    date: "2025-12-28",
    order: 70,
  ),
)<frontmatter>
#import "../../../../../typst-theme.c.typ": project
#show: project


= Consolidation & Overlapping Chunks

These techniques focus on manipulating chunk boundaries and triggering consolidation (merging) to create "ghost" chunks that encompass other active allocations.

#figure(
  table(
    columns: (auto, 1fr),
    inset: 10pt,
    align: horizon,
    [*Technique*], [*Description*],
    [Overlapping Chunks], [Simple size overwrite to expand a chunk.],
    [Non-adjacent Consolidation], [Consolidating across an allocated chunk.],
    [Poison Null Byte], [Shrinking a chunk via off-by-one null byte.],
    [House of Einherjar], [Triggering massive backward consolidation.],
    [Mmap Overlap], [Achieving overlap in the mmap region.],
  ),
  caption: [Attacks centered on consolidation and overlap.],
)
