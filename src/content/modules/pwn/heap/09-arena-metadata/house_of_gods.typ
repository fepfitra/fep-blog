#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Gods",
    description: "An arena hijacking technique that replaces the thread_arena with a fake arena by exploiting binmap and unsorted bin attacks.",
    date: "2025-12-28",
    order: 81,
  ),
)<frontmatter>

= House of Gods

== Introduction

"House of Gods" is a sophisticated arena hijacking technique targeting glibc versions earlier than 2.27. The primary goal of this attack is to gain an arbitrary write against the `thread_arena` symbol of the main thread. By doing so, an attacker can replace the `main_arena` with a carefully crafted fake arena, leading to arbitrary code execution.

The attack leverages a minor bug in glibc related to how arenas are reused when the arena limit (`narenas_limit`) is exceeded. It combines a "Binmap Attack" to gain control over arena metadata with an "Unsorted Bin Attack" to corrupt the arena count.

== Prerequisites
- **Glibc < 2.27**: Tested on versions 2.23 through 2.26.
- **8-11 Allocations**: A small number of allocations is sufficient to trigger the hijacking.
- **Write-After-Free (WAF)**: A single WAF on an unsorted chunk is required.
- **Leaks**: Knowledge of heap and libc addresses is mandatory.
- **Userdata Control**: Control over the first 5 quadwords of a chunk's userdata.

== Example from `house_of_gods.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main(void) {
    void *SMALLCHUNK = malloc(0x88);
    void *FAST20 = malloc(0x18);
    void *FAST40 = malloc(0x38);

    free(SMALLCHUNK);
    malloc(0x98); 

    SMALLCHUNK = malloc(0x88);
    free(SMALLCHUNK);

    // VULNERABILITY: Redirect to binmap
    *((uint64_t*) (SMALLCHUNK + 0x8)) = libc_leak + 0x7f8; 

    void *BINMAP = malloc(0x1f8);

    void *INTM = malloc(0x98);

    // VULNERABILITY: Unsorted bin attack on narenas
    *((uint64_t*) (INTM + 0x8)) = libc_leak - 0xa20; 
    malloc(0x98); 

    // VULNERABILITY: Inject fake arena
    *((uint64_t*) (BINMAP + 0x8)) = (uint64_t) (fake_arena);

    malloc(0xffffffffffffffbf + 1);
    malloc(0xffffffffffffffbf + 1);

    return 0;
}
```

== Attack Flow Explained

=== 1. The Binmap Attack
Glibc maintains a `binmap` bitmask in the arena to quickly identify which bins contain free chunks. By placing chunks into specific smallbins or largebins, the attacker can "set" bits in the `binmap` field within the `main_arena`.

If carefully manipulated, these bits can be interpreted as a valid `size` field for a fake chunk that overlaps with the `main_arena` structure itself.

=== 2. Overlapping the Arena
Using a Write-After-Free vulnerability, the attacker links this "binmap chunk" into the unsorted bin. A subsequent `malloc` call for the matching size returns a pointer that overlaps with the `main_arena`. This grants the attacker write access to critical arena fields like `main_arena.next` and `main_arena.system_mem`.

=== 3. Corrupting `narenas`
The attacker performs a standard Unsorted Bin Attack to overwrite the `narenas` global variable with a very large value (a libc address). This tricks the allocator into believing that the maximum number of arenas has been reached and exceeded.

=== 4. Triggering `reused_arena()`
When a thread's current arena cannot satisfy an allocation request (e.g., because the request is for an impossibly large amount of memory), glibc calls `reused_arena()` to find another arena to use.

Because `narenas` is now larger than `narenas_limit`, glibc traverses the `arena.next` linked list to find an available arena. Since the attacker has overwritten `main_arena.next` with the address of a fake arena, `reused_arena()` will eventually select this fake arena and update the thread's `thread_arena` pointer to it.

=== 5. Arbitrary Allocation/Write
Once `thread_arena` points to a fake arena controlled by the attacker, all subsequent `malloc` and `free` operations by that thread will use the attacker's metadata. The attacker can then easily return an arbitrary pointer (e.g., to the stack or global offset table) by crafting fastbins or tcache bins within the fake arena.
