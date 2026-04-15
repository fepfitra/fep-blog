---
title: "Small & Large Bin Attacks"
description: "Techniques targeting the sorted small and large bins for complex heap manipulation."
date: "2025-12-28"
order: 50
---

# Small & Large Bin Attacks

Sorted bins (small and large) have more complex metadata and stricter checks than fastbins, but offer powerful primitives once these checks are bypassed.

| Technique | Description |
| --- | --- |
| House of Lore | Small bin BK pointer corruption for arbitrary allocation. |
| Large Bin Attack | Exploiting sorting logic to write heap addresses. |

**Exploits targeting small and large sorted bins.**
