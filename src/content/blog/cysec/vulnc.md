---
title: "2025 Search"
description: "Cheatsheet"
date: "2025-8-3"
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
