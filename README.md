# pe_ep_intercept

Creates a new section. Entry point is modified with new section's virtual address. A new entry point is assembled
with the original entry point (oep) using Keystone. Consideration is given with address space layout randomisation (ASLR).

Two approaches for ASLR:
1. Use peb (`fs[30h]`) -> loaded modules -> base address -> bitwise-or oep with base address. [Based on this post][1].
2. Add new entries to relocation table.

The modified program jumps to the adjusted oep allowing normal execution of the program.

[1]: https://illicitcoding.wordpress.com/2013/02/05/getting-the-base-address-of-a-dllexe-w-aslr-enabled/

Final goal:
1. To be able to write new functions to an executable.
2. To work with both x86 and x86-64.
3. Allow modification to the import table for new thunk entries or libraries.