#metadata(
  (
    title: "Kernel Level 4",
    description: "Writeup for Kernel Level 4",
    date: "2026-01-01",
    order: 4,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project



#table(
  columns: (auto, 1fr),
  inset: 10pt,
  align: (right, left),
  [*Title*], [Kernel Buffer Overflow],
  [*Date*], [2025-12-30],
  [*Description*],
  [Exploiting a buffer overflow in a kernel module to overwrite control data or trigger a 'win' function.],
)

= Babykernel Level 4

== Introduction

This challenge introduces the concept of buffer overflows in the kernel.

== Vulnerability Analysis

The kernel module contains a function that copies user-space data into a fixed-size kernel buffer without proper bounds checking. This allows us to overwrite adjacent memory, including function pointers or other critical state variables.

== Exploitation Steps

=== 1. Calculating Overflow Offset
We determine the size of the kernel buffer and the distance to the target variable or function pointer.

=== 2. Overwriting the Target
By sending a payload that exceeds the buffer's capacity, we overwrite the desired memory location.

```bash
# Example of sending a large payload
python3 -c 'print("A"*64 + "\x5b\x00\x00\x00")' > /proc/pwncollege
```

=== 3. Escalation
The overwritten state triggers the `win` function, leading to privilege elevation.

