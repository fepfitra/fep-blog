#metadata(
  (
    title: "Decrypting Safe-Linking",
    description: "A technique to recover the original pointer from a Safe-Linking-protected value in glibc 2.32+.",
    date: "2025-12-28",
    order: 4,
  ),
)<frontmatter>
#import "../../../../../typst-theme.c.typ": project
#show: project


= Decrypting Safe-Linking

== Introduction

Starting from glibc 2.32, a security mitigation called *Safe-Linking* was introduced to protect single-linked lists (specifically tcache and fastbins). It masks the next-chunk pointer (`fd`) by XORing it with the address of the pointer itself, shifted right by 12 bits.

If a pointer `P` is stored at address `L`, the stored value `V` is:
$V = (L >> 12) xor P$

This document demonstrates how to reverse this operation and recover the original pointer `P`, which is often necessary for heap exploitation when a heap leak is not fully available or when verifying corrupted pointers.

== The Decryption Logic

The key observation is that heap addresses are typically 12-bit aligned (4KB pages). The topmost 12 bits of $(L >> 12)$ are zeroes. Therefore, the topmost 12 bits of the stored value $V$ are identical to the topmost 12 bits of the original pointer $P$. We can then use these recovered bits to XOR the next 12-bit block, and so on, until the entire pointer is recovered.

== Example from `decrypt_safe_linking.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

long decrypt(long cipher)
{
	long key = 0;
	long plain;

	for(int i=1; i<6; i++) {
		int bits = 64-12*i;
		if(bits < 0) bits = 0;
		plain = ((cipher ^ key) >> bits) << bits;
		key = plain >> 12;
	}
	return plain;
}

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	long *a = malloc(0x20);
	long *b = malloc(0x20);
	malloc(0x10);

	free(a);
	free(b);

	long plaintext = decrypt(b[0]);

	assert(plaintext == (long)a);
	return 0;
}
```

== How it Works

The decryption works in rounds, processing 12 bits at a time from most significant to least significant.

1.  *Round 1*: The bits 63-52 of the key $(L >> 12)$ are `0`. Thus, bits 63-52 of `plain` are simply `cipher & 0xFFF0000000000000`.
2.  *Round 2*: We shift the recovered `plain` bits right by 12 to get the next part of the key. We XOR this with `cipher` to recover bits 51-40.
3.  *Subsequent Rounds*: We repeat this process until all 64 bits are recovered.

This recursive XOR decryption is effective because the "key" (the address shifted by 12) and the "plaintext" (the pointer) often share the same top bits, and the 12-bit right shift creates a predictable dependency chain that can be unwound.

== Prerequisites
- *Safe-Linking Enabled*: Glibc 2.32 or later.
- *Page Alignment*: The attack works best when the chunk address and the stored pointer share the same 4KB page boundary, which is the common case for heap allocations.
