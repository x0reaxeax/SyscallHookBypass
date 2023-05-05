# SyscallHookBypass

### NtAllocateVirtualMemory
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

### NtSetInformationProcess

Patches the `call` instruction at `kernelbase!SetProcessInformation+0xDB`, ... blah, blah, same thing over and over again, you get the picture... in order to set current process as **critical**.  
I took a lazy route with this one, because `SetProcessInformation` rejects `ProcessBreakOnTermination` flag, so in this one we're langing straight on top of the fugazi stub in `KernelBase`.  
Since we're skipping all the meal prep that `SetProcessInformation` does before calling the NTCALL `NtSetInformationProcess`, we're gonna segfault very soon after returning from `NTDLL`, which will of course result in a BSOD with stopcode `CRITICAL_PROCESS_DIED`. The way around this is to patch all the conditional jumps inside `SetProcessInformation`, before the `call` takes place, but since the purpose of this is to BSOD anyway, it is literally pointless for me to bother with this.  

Tested on Win10 x64 22H2 (19045.2728)  
KernelBase.dll version 10.0.19041.2728

### NtWriteVirtualMemory

Self-explanatory. Offset is `KERNELBASE.DLL!WriteProcessMemory+0xB7`.  
Usage: `NtWriteVirtualMemory.exe <pid> <address>`  

Tested on Win10 x64 21H2 (19044.2846) 
KernelBase.dll version 10.0.19041.2788
