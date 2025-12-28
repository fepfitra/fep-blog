#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Io",
    description: "A technique for glibc 2.29-2.33 that exploits the tcache 'key' field to leak and corrupt the tcache_perthread_struct via Use-After-Free.",
    date: "2025-12-28",
    order: 22,
  ),
)<frontmatter>

= House of Io

== Introduction

"House of Io" is a heap exploitation technique that targets glibc versions 2.29 through 2.33. It exploits a specific behavior of the tcache implementation where a freed chunk's `key` field (the second slot in the chunk's user data) is populated with a pointer to the `tcache_perthread_struct` (the tcache management structure).

By combining a Use-After-Free (UAF) vulnerability with this leaked pointer, an attacker can directly manipulate the tcache metadata. This allows for a **Tcache Metadata Poisoning** attack, even without a direct heap leak or large overflow, as the management structure's address is provided directly by the allocator itself.

== The Mechanism

When a chunk is freed into the tcache:
1.  The `next` pointer (first slot) points to the previous head of the bin.
2.  The `key` pointer (second slot) is set to the address of the thread's `tcache_perthread_struct`.

In glibc versions 2.29-2.33, this `key` served as a check for double-frees. If an attacker can read or write to this `key` field after the chunk is freed (via UAF), they can locate and corrupt the entire tcache management system.

== Example from `house_of_io.c`

```c
#include <assert.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct overlay {
  uint64_t *next;
  uint64_t *key; 
};

struct tcache_perthread_struct {
  uint16_t counts[64];
  uint64_t entries[64];
};

int main() {
  struct overlay *ptr = malloc(sizeof(struct overlay));

  free(ptr);

  // UAF: Leak management struct pointer
  struct tcache_perthread_struct *management_struct =
      (struct tcache_perthread_struct *)ptr->key;

  // VULNERABILITY: Corrupt management struct
  management_struct->counts[0] = 1;
  management_struct->entries[0] = (uint64_t)&global_var;

  uint64_t *evil_chunk = malloc(0x10);
  assert(evil_chunk == &global_var);
}
```

== Attack Flow Explained

=== 1. Allocation and Free
The attacker allocates a chunk and then frees it. Because it's a tcache-sized chunk, glibc places it in the tcache and sets its `key` field to point to the `tcache_perthread_struct`.

=== 2. Leaking Metadata Address
Using a Use-After-Free read primitive, the attacker reads the value at `ptr + 8`. This value is the absolute address of the tcache management structure on the heap.

=== 3. Corrupting Metadata
Using a Use-After-Free write primitive (or by having the leaked address), the attacker writes directly to the `tcache_perthread_struct`:
- They set a bin's `count` to 1.
- They set that bin's `entry` (the head pointer) to their target address.

=== 4. Arbitrary Allocation
The next `malloc` request for that size will be served by the corrupted tcache metadata, returning the attacker's target pointer.

== Comparison with Tcache Metadata Poisoning

While **Tcache Metadata Poisoning** is the "goal," House of Io is the "method" to achieve it when a direct leak is unavailable. It relies specifically on the `key` field behavior present in glibc 2.29-2.33.

| Feature | Tcache Metadata Poisoning | House of Io |
| :--- | :--- | :--- |
| **Glibc Versions** | Any (with tcache) | 2.29 - 2.33 |
| **Primitive** | Direct write to metadata | UAF on freed tcache chunk |
| **Leak Required** | Heap leak (to find metadata) | **None** (metadata address is leaked via `key`) |
| **Safe-Linking** | Bypasses (direct metadata write) | Bypasses (direct metadata write) |

Note: In glibc 2.34+, the `key` value was changed to a random cookie to prevent this specific leak and complicate double-free detection.
