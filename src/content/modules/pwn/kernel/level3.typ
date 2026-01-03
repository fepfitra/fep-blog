#metadata(
  (
    title: "Kernel Level 3",
    description: "Writeup for Kernel Level 3",
    date: "2026-01-01",
    order: 3,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project



#table(
  columns: (auto, 1fr),
  inset: 10pt,
  align: (right, left),
  [*Title*], [Kernel Buffer Interaction],
  [*Date*], [2025-12-30],
  [*Description*],
  [Manipulating kernel module state by writing to its provided buffer interface.],
)

= Babykernel Level 3

== Introduction

This challenge requires a more direct manipulation of the kernel module's memory, typically through a buffer exposed via `/proc` or a character device.

== Vulnerability Analysis

The kernel module maintains an internal buffer and state. By writing a specific sequence of bytes or a correctly formatted structure, we can influence the module's control flow to call the `win` function.

== Exploitation Steps

=== 1. Satisfying Buffer Requirements
We write the necessary data to the module's interface.

```bash
echo -n "..." > /proc/pwncollege
```

=== 2. Triggering the Win Condition
Once the state is correctly set, the module executes its privilege elevation logic.

