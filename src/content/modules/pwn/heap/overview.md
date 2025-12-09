---
title: "Heap Exploitation Overview"
description: "An overview of heap exploitation techniques, largely based on the how2heap repository."
date: 2025-12-09
order: 0
---

## Heap Exploitation

This section is dedicated to understanding and exploiting heap-based vulnerabilities in modern memory allocators, with a strong emphasis on the techniques demonstrated in the `how2heap` repository.

### Inspiration: how2heap

`how2heap` is a comprehensive collection of heap exploitation techniques compiled by the Shellphish group. It serves as an essential learning resource for security researchers and CTF players. The repository provides practical examples for various heap vulnerabilities, primarily focusing on the GNU C Library (glibc) allocator (ptmalloc).

The examples in this section are heavily inspired by `how2heap` and aim to provide a clear and concise explanation of each technique. We will explore the inner workings of the heap, understand how different vulnerabilities arise, and learn how to exploit them effectively.

### Covered Topics

This module will cover a range of heap exploitation techniques, including but not limited to:

*   **Basic Concepts:** Understanding chunks, bins, and the allocation/deallocation process.
*   **Classic Vulnerabilities:** Techniques like use-after-free, double free, and heap overflow.
*   **Advanced Exploits:** More complex techniques such as fastbin attacks, tcache poisoning, and the "House of" series of exploits.

By studying these examples, you will gain a solid understanding of heap internals and be better equipped to identify and exploit heap-related security flaws.
