#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Tcache Metadata Poisoning",
    description: "Gaining full control over tcache by corrupting the tcache_perthread_struct metadata, allowing for immediate arbitrary allocations.",
    date: "2025-12-28",
    order: 21,
  ),
)<frontmatter>

= Tcache Metadata Poisoning

== Introduction

The tcache system is managed by a special structure called `tcache_perthread_struct`. This structure is itself stored on the heap, typically as the very first chunk allocated when a thread first uses `malloc`. It contains two critical arrays:
1.  `counts`: An array of 16-bit integers representing the number of chunks currently in each tcache bin.
2.  `entries`: An array of pointers, each being the head of the linked list for a specific tcache bin.

If an attacker can gain write access to this metadata chunk (e.g., via a heap overflow or a large relative write), they gain absolute control over the tcache. By simply writing a target address into an `entries` slot and setting the corresponding `counts` to at least 1, the next `malloc` for that size will immediately return the target address.

== The Metadata Structure

On a 64-bit system, the structure looks like this:

```c
struct tcache_perthread_struct {
  uint16_t counts[TCACHE_BINS]; // 64 bins * 2 bytes = 128 bytes (0x80)
  tcache_entry *entries[TCACHE_BINS]; // 64 bins * 8 bytes = 512 bytes (0x200)
};
```

The total size is `0x280` bytes, plus the chunk header (`0x10`), resulting in a `0x290` sized chunk.

== Example from `tcache_metadata_poisoning.c`

```c
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct tcache_metadata {
  uint16_t counts[64];
  void *entries[64];
};

int main() {
  uint64_t stack_target = 0x1337;
  
  // Allocate a chunk to find the heap base
  uint64_t *victim = malloc(0x10);
  
  // Calculate the base of the tcache metadata
  // It's the first chunk on the heap
  long metadata_size = sizeof(struct tcache_metadata);
  struct tcache_metadata *metadata =
      (struct tcache_metadata *)((long)victim - 0x10 - metadata_size);

  // VULNERABILITY: Overwriting metadata
  // We insert our target address into the 0x20 bin (index 1)
  metadata->counts[1] = 1;
  metadata->entries[1] = &stack_target;

  // The next malloc(0x20) returns the stack target immediately
  uint64_t *evil = malloc(0x20);
  
  assert(evil == &stack_target);
}
```

== Attack Flow Explained

=== 1. Locating the Metadata
The `tcache_perthread_struct` is usually the first allocation on the heap. An attacker with a heap leak can calculate its address. In this example, since `victim` is the first user allocation, the metadata is located exactly `sizeof(tcache_perthread_struct) + header_size` bytes before it.

=== 2. Corrupting the Bins
By writing to the `metadata` pointer:
- We set `counts[1]` to `1`. This tells `malloc` that the `0x20` bin (index 1) is not empty.
- We set `entries[1]` to `&stack_target`. This sets the head of the `0x20` bin to our target address.

=== 3. Arbitrary Allocation
When `malloc(0x20)` is called:
1.  It calculates the tcache index (1).
2.  It checks `tcache->counts[1]`. It finds `1` (which we wrote).
3.  It retrieves the pointer from `tcache->entries[1]`.
4.  It returns our `stack_target` address.

== Security Implications

This attack is extremely powerful because it bypasses almost all tcache-specific mitigations. It doesn't require freeing chunks or dealing with Safe-Linking (as we are writing to the metadata entry directly, not to a chunk's `next` pointer). It effectively provides an "instant" arbitrary allocation once the metadata address is known and writable. Techniques like **House of Water** often aim for this level of control as their ultimate goal.
