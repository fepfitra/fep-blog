---
title: "Top Chunk Attacks"
description: "Techniques targeting the wilderness (top chunk) and the sysmalloc extension mechanism."
date: "2025-12-28"
order: 80
---

# Top Chunk (Wilderness) Attacks

The top chunk is the final boundary of the heap. Corrupting it can force the allocator to behave unexpectedly during heap growth.

| Technique | Description |
| --- | --- |
| House of Force | The original arbitrary-malloc wilderness attack. |
| sysmalloc `_int_free` | Implicitly freeing the top chunk into unsorted bin. |
| House of Orange | The legendary top chunk corruption + FSOP. |
| House of Tangerine | Modern House of Orange for recent glibc. |

**Exploits targeting the wilderness and sysmalloc.**
