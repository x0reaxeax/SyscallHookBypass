# SyscallHookBypass
Patches the `call` instruction at `kernelbase!VirtualAlloc+0x41` by placing legitimate NTAPI stub at the same address and moving the rest of the function down 8 bytes (stub size).  
The `RIP` relative offset for `call QWORD PTR ds:[&ZwAllocateVirtualMemory]` is recalculated and the pointer to the NTAPI call is patched to always land at `syscall` instruction, effectively skipping over installed trampolines.  
Stack trace of patched call:
```
[0x0]   ntdll!NtAllocateVirtualMemory + 0x12   
[0x1]   KERNELBASE!VirtualAlloc + 0x4f   [non-standard offset could be potentially a detection vector]
[0x2]   NtAllocateVirtualMemory!main + 0x24e   
[0x3]   NtAllocateVirtualMemory!invoke_main + 0x22   
[0x4]   NtAllocateVirtualMemory!__scrt_common_main_seh + 0x10c   
[0x5]   KERNEL32!BaseThreadInitThunk + 0x14   
[0x6]   ntdll!RtlUserThreadStart + 0x21   
```

Tested on Win10 x64 21H2 (19044.2728)
