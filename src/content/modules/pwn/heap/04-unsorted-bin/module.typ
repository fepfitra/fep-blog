#metadata(
  (
    title: "04-Unsorted Bin Attacks",
    description: "Exploiting the unsorted bin's removal logic to achieve powerful write primitives.",
    date: "2025-12-28",
    order: 0,
  ),
)<frontmatter>
#import "../../../../../typst-theme.c.typ": project
#show: project


= Unsorted Bin Attacks

The unsorted bin is a temporary holding area for freed chunks. Its insertion and removal logic can be abused to write large values or libc addresses to arbitrary locations.

#figure(
  table(
    columns: (auto, 1fr),
    inset: 10pt,
    align: horizon,
    [*Technique*], [*Description*],
    [Unsorted Bin Attack], [Writing a large libc address to any location.],
    [Into Stack], [Tricking the bin into returning stack memory.],
    [Unsafe Unlink], [Exploiting backward/forward consolidation for arbitrary write.],
  ),
  caption: [Exploits targeting the unsorted bin.],
)
