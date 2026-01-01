#metadata(
  (
    title: "Environment Setup",
    description: "Setting up a minimal kernel pwn environment.",
    date: "2026-01-01",
    order: 2,
  ),
)<frontmatter>
#import "../../../../typst-theme.c.typ": project
#show: project

= Minimal Kernel Pwn Orchestrator

This #link("https://github.com/fepfitra/kernel-pwn-minimal")[repository] contains a standalone environment for testing kernel exploits.

== Structure
- `bzImage`: The kernel image.
- `busybox`: Multi-call binary for the rootfs utilities.
- `chall/`: Directory containing the challenge kernel module.
- `exploit/`: Directory containing exploit source files (all `.c` files here are compiled).
- `linux-5.4/`: Kernel source tree.
- `pack.sh`: Script to compile the exploit and generate the `initramfs.cpio.gz`.
- `run.sh`: Script to launch the QEMU environment.
- `rootfs/`: The directory structure used to build the initramfs.
- `src/`: Source code for testing/debugging modules.

== Usage
=== 1. Prepare your exploit
Place your exploit source files in the `exploit/` directory (e.g., `exploit/exploit.c`). Any `.c` file in this directory will be automatically compiled and added to the rootfs. The template `exploit/exploit.c` already handles:
- Dynamic symbol lookup via `/proc/kallsyms` (KASLR bypass).
- User-space shellcode mapping (`mmap`).
- Silent privilege check and shell spawning.

=== 2. Build and Pack
Run the packing script to compile your C code and create the compressed filesystem:
```bash
./pack.sh
```

=== 3. Launch QEMU
Run the environment. You can toggle security mitigations using arguments:
```bash
./run.sh # Default: nokaslr nopti
./run.sh kaslr # Enable KASLR
./run.sh pti # Enable PTI (Isolation)
./run.sh full # Enable both KASLR and PTI
```

== Debugging with GDB
... (existing instructions) ...

== Viewing Memory Mappings (Virtual Memory)
Since `info proc mappings` is not supported in kernel mode, use the QEMU monitor:
1. In the QEMU terminal, press `Ctrl-a` then `c` to enter the monitor.
2. Type `info mem` to see mapped virtual memory ranges.
3. Type `info tlb` for page table details.
4. Press `Ctrl-a` then `c` again to return to the guest.
