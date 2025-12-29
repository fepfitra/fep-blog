#metadata(
  (
    title: "Fastbin Reverse into Tcache",
    description: "Abusing the fastbin-to-tcache refill mechanism to achieve an arbitrary allocation or write a heap pointer to a target location.",
    date: "2025-12-28",
    order: 51,
  ),
)<frontmatter>
#import "../../../../../typst-theme.c.typ": project
#show: project


= Fastbin Reverse into Tcache

== Introduction

This attack exploits the mechanism in glibc where the tcache is refilled from the fastbins. When the tcache for a particular size is empty and a `malloc` request for that size is made, glibc may refill the tcache by pulling chunks from the corresponding fastbin.

Crucially, the chunks are pulled from the fastbin and pushed into the tcache. Since both are LIFO (Last-In First-Out) structures, but the refill process iterates through the fastbin and pushes each chunk onto the tcache, the order of chunks is reversed. By corrupting a `fd` pointer in the fastbin, an attacker can trick this refill logic into "stashing" an arbitrary address into the tcache.

== Prerequisites
- *Heap Leak (glibc 2.32+)*: Due to Safe-Linking, the fastbin `fd` pointer must be XORed with its own address.
- *Write Primitive*: Ability to overwrite the `fd` pointer of a chunk in the fastbin (e.g., via UAF or Heap Overflow).
- *Tcache Control*: Ability to fill and then empty the tcache for a specific size.

== Example from `fastbin_reverse_into_tcache.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

const size_t allocsize = 0x40;

int main(){
	setbuf(stdout, NULL);

	char* ptrs[14];
	size_t i;
	for (i = 0; i < 14; i++) {
		ptrs[i] = malloc(allocsize);
	}
	
	// Fill tcache
	for (i = 0; i < 7; i++) free(ptrs[i]);
	
	char* victim = ptrs[7];
	free(victim);
	
	// Fill fastbin
	for (i = 8; i < 14; i++) free(ptrs[i]);
	
	size_t stack_var[6];
	memset(stack_var, 0xcd, sizeof(stack_var));
	
	// VULNERABILITY: Corrupt fastbin fd
	*(size_t**)victim = (size_t*)((long)&stack_var[0] ^ ((long)victim >> 12));
	
	// Empty tcache
	for (i = 0; i < 7; i++) ptrs[i] = malloc(allocsize);
	
	// Trigger reverse refill
	malloc(allocsize);
	
	char *q = malloc(allocsize);
	
	assert(q == (char *)&stack_var[2]);
	return 0;
}
```

== Attack Flow Explained

=== 1. Filling Tcache and Fastbin

First, we allocate several chunks. We free 7 of them to fill the tcache for that size. Then, we free the `victim` chunk and several others. Since the tcache is full, these chunks go into the fastbin.

The fastbin list looks like this (LIFO):
`HEAD -> ptrs[13] -> ptrs[12] -> ... -> victim -> NULL`

=== 2. Corrupting the Fastbin Pointer

We use a vulnerability to overwrite the `fd` pointer of the `victim` chunk. We point it to a location we want to control (minus the header size), such as a stack address. In glibc 2.32+, we must account for Safe-Linking.

```c
*(size_t**)victim = (size_t*)((long)&stack_var[0] ^ ((long)victim >> 12));
```

The fastbin list is now:
`HEAD -> ptrs[13] -> ... -> victim -> &stack_var[0]`

=== 3. Emptying Tcache and Triggering Refill

We allocate 7 times to empty the tcache. The next `malloc` request finds the tcache empty and looks at the fastbin.

glibc takes the head of the fastbin (`ptrs[13]`) to satisfy the current `malloc` request. It then notices the tcache is empty and tries to refill it using the remaining chunks in the fastbin (up to 7).

=== 4. Reverse Refill Mechanism

The refill logic iterates through the fastbin and pushes each chunk onto the tcache:
1. `ptrs[12]` is pushed to tcache.
2. ...
3. `victim` is pushed to tcache.
4. `&stack_var[0]` (the corrupted pointer) is pushed to tcache.

Because tcache is also a LIFO, the *last* thing pushed becomes the *head*. So the tcache head now points to our target address.

=== 5. Result

The stashing process writes the address of the *next* chunk in the list to the `fd` field of the current chunk. When it stashes our target address, it writes a heap pointer (the address of the chunk that was previously at the head) into the target location.

Finally, the next `malloc` call returns the pointer to our target address (`&stack_var[2]`).