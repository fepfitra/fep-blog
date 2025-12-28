#metadata(
  (
    title: "Stashing & Hybrid Attacks",
    description: "Exploiting the interaction between different bin types, such as fastbin-to-tcache refill.",
    date: "2025-12-28",
    order: 0,
  ),
)<frontmatter>
#import "../../../../../typst-theme.c.typ": project
#show: project


= Stashing & Hybrid Attacks

These attacks exploit the "stashing" and "refill" mechanisms where glibc moves chunks between different bin levels (e.g., from fastbin to tcache).

#figure(
  table(
    columns: (auto, 1fr),
    inset: 10pt,
    align: horizon,
    [*Technique*], [*Description*],
    [Stashing Unlink], [Hijacking the smallbin-to-tcache refill.],
    [Reverse Refill], [Poisoning the fastbin-to-tcache stashing logic.],
    [House of Storm], [A hybrid unsorted + large bin attack.],
  ),
  caption: [Exploits leveraging bin interaction and stashing.],
)
