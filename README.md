# pe_ep_intercept
[![Build Status](https://travis-ci.org/raffclar/pe_ep_intercept.svg?branch=master)](https://travis-ci.org/raffclar/pe_ep_intercept)

Writes a new entry point for a target executable using Keystone as the assembler.

### Table of Contents
* **[Why does this exist](#Why-does-this-exist)**
* **[Details](#Details)**
* **[How to msvc_cmd](#How-to-msvc_cmd)**

### Why does this exist
I found it difficult to find a portable executable patcher that handles a random base address and doesn't use inline assembly for the copied instructions. It was also difficult to find a patcher that does not store compiled x86 or x86-64 machine code in the source.

### Details

Creates a new section marked as executable. The program's entry point is modified with the new section's virtual address. A new entry point is assembled
with the original entry point (oep) using Keystone. Consideration is given with address space layout randomisation (ASLR) for the base address.

Two approaches for ASLR base address:
1. Using the PEB (`fs[30h]` or `gs[60h]`) -> loader data structure -> base address + oep. [Based on this post][1].
2. Add new entries to relocation table.

The newly added section's code jumps to the original oep allowing normal execution of the program.

### How to msvc_cmd

1. Ensure that you have Cmake installed.
2. Execute `run_build.sh`.
3. A directory called "build" will be created that contains the compiled program

[1]: https://illicitcoding.wordpress.com/2013/02/05/getting-the-base-address-of-a-dllexe-w-aslr-enabled/
