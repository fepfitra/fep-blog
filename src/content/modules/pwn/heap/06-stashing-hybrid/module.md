---
title: "Stashing & Hybrid Attacks"
description: "Exploiting the interaction between different bin types, such as fastbin-to-tcache refill."
date: "2025-12-28"
order: 60
---

# Stashing & Hybrid Attacks

These attacks exploit the "stashing" and "refill" mechanisms where glibc moves chunks between different bin levels (e.g., from fastbin to tcache).

| Technique | Description |
| --- | --- |
| Stashing Unlink | Hijacking the smallbin-to-tcache refill. |
| Reverse Refill | Poisoning the fastbin-to-tcache stashing logic. |
| House of Storm | A hybrid unsorted + large bin attack. |

**Exploits leveraging bin interaction and stashing.**
