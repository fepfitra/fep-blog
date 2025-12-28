#metadata(
  (
    title: "Tcache Attacks",
    description: "Exploiting the Thread Local Cache (tcache) for fast and effective heap corruption.",
    date: "2025-12-28",
    order: 0,
  ),
)<frontmatter>
#import "../../../../../typst-theme.c.typ": project
#show: project


= Tcache Attacks

The Thread Local Cache (tcache), introduced in glibc 2.26, is a high-performance caching layer that provides fertile ground for exploitation due to its simplified management and fewer integrity checks.

#figure(
  table(
    columns: (auto, 1fr),
    inset: 10pt,
    align: horizon,
    [*Technique*], [*Description*],
    [Tcache Poisoning], [Overwriting next pointers for arbitrary allocations.],
    [House of Spirit], [Tricking free into accepting stack pointers.],
    [Metadata Poisoning], [Directly corrupting the tcache_perthread_struct.],
    [House of Io], [Exploiting the tcache key field for UAF.],
    [House of Water], [Advanced tcache metadata hijacking.],
  ),
  caption: [Exploits targeting the tcache layer.],
)
