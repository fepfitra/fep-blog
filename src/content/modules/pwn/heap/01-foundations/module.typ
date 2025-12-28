#metadata(
  (
    title: "01-Foundations",
    description: "Core concepts, algorithms, and primitive techniques of the glibc heap allocator.",
    date: "2025-12-28",
    order: 0,
  ),
)<frontmatter>
#import "../../../../../typst-theme.c.typ": project
#show: project


= Heap Foundations

This section covers the fundamental principles of the glibc heap allocator, including its internal structure, algorithms, and common primitives used in heap exploitation.

#figure(
  table(
    columns: (auto, 1fr),
    inset: 10pt,
    align: horizon,
    [*Technique*], [*Description*],
    [Overview], [Visual guide to chunk anatomy and allocator behavior.],
    [Cheatsheet], [Reference for common heap commands and structures.],
    [First-Fit], [Understanding the basic allocation strategy.],
    [Tcache Index], [How glibc calculates bin indices for small chunks.],
    [Safe-Linking], [Decryption and logic of the modern pointer protection.],
  ),
  caption: [Foundational topics in glibc heap.],
)
