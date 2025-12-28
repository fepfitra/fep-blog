#metadata(
  (
    title: "03-Fastbin Attacks",
    description: "Classical heap exploits targeting the fastbins, the original LIFO caching mechanism.",
    date: "2025-12-28",
    order: 0,
  ),
)<frontmatter>
#import "../../../../../typst-theme.c.typ": project
#show: project


= Fastbin Attacks

Fastbins are the classical caching mechanism in glibc. While partially superseded by tcache in modern versions, they remain relevant when tcache is exhausted or disabled.

#figure(
  table(
    columns: (auto, 1fr),
    inset: 10pt,
    align: horizon,
    [*Technique*], [*Description*],
    [Fastbin Dup], [The classic double-free leading to overlapping chunks.],
    [Dup into Stack], [Escalating a double-free to gain stack control.],
    [Dup Consolidate], [Bypassing size checks via malloc_consolidate.],
    [House of Spirit], [The original fastbin stack-allocation attack.],
  ),
  caption: [Exploits targeting the fastbin system.],
)
