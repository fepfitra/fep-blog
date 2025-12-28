#metadata(
  (
    title: "Advanced & Leakless",
    description: "Specialized exploitation techniques that bypass modern hardening or work without memory leaks.",
    date: "2025-12-28",
    order: 100,
  ),
)<frontmatter>
#import "../../../../../typst-theme.c.typ": project
#show: project


= Advanced & Leakless Techniques

This section hosts specialized attacks that demonstrate advanced concepts, such as bypassing ASLR without a leak or targeting specific modern mitigations.

#figure(
  table(
    columns: (auto, 1fr),
    inset: 10pt,
    align: horizon,
    [*Technique*], [*Description*],
    [House of Roman], [Leakless heap exploitation via relative overwrites.],
  ),
  caption: [Advanced and leakless heap techniques.],
)
