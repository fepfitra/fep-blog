#metadata(
  (
    title: "Arena & Metadata Hijacking",
    description: "High-level attacks that target the allocator's internal state structures and multi-arena management.",
    date: "2025-12-28",
    order: 90,
  ),
)<frontmatter>
#import "../../../../../typst-theme.c.typ": project
#show: project


= Arena & Metadata Hijacking

These advanced techniques target the global `malloc_state` structures, allowing an attacker to completely hijack the allocator's behavior for a thread or the entire process.

#figure(
  table(
    columns: (auto, 1fr),
    inset: 10pt,
    align: horizon,
    [*Technique*], [*Description*],
    [House of Mind], [Abusing non-main arenas for arbitrary writes.],
    [House of Gods], [Hijacking the thread_arena via binmap corruption.],
  ),
  caption: [Exploits targeting the arena and global metadata.],
)
