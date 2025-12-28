#metadata(
  (
    title: "05-Small & Large Bin Attacks",
    description: "Techniques targeting the sorted small and large bins for complex heap manipulation.",
    date: "2025-12-28",
    order: 50,
  ),
)<frontmatter>
#import "../../../../../typst-theme.c.typ": project
#show: project


= Small & Large Bin Attacks

Sorted bins (small and large) have more complex metadata and stricter checks than fastbins, but offer powerful primitives once these checks are bypassed.

#figure(
  table(
    columns: (auto, 1fr),
    inset: 10pt,
    align: horizon,
    [*Technique*], [*Description*],
    [House of Lore], [Small bin BK pointer corruption for arbitrary allocation.],
    [Large Bin Attack], [Exploiting sorting logic to write heap addresses.],
  ),
  caption: [Exploits targeting small and large sorted bins.],
)
