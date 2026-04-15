---
title: "Consolidation & Overlap"
description: "Abusing the allocator's merging logic to create overlapping chunks and cross-allocation control."
date: "2025-12-28"
order: 70
---

# Consolidation & Overlapping Chunks

These techniques focus on manipulating chunk boundaries and triggering consolidation (merging) to create "ghost" chunks that encompass other active allocations.

| Technique | Description |
| --- | --- |
| Overlapping Chunks | Simple size overwrite to expand a chunk. |
| Non-adjacent Consolidation | Consolidating across an allocated chunk. |
| Poison Null Byte | Shrinking a chunk via off-by-one null byte. |
| House of Einherjar | Triggering massive backward consolidation. |
| Mmap Overlap | Achieving overlap in the mmap region. |

**Attacks centered on consolidation and overlap.**
