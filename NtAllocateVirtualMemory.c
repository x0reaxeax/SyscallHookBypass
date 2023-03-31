#include <stdio.h>
#include <Windows.h>

#define NTCALL_OFFSET   0x41
#define RIP_DS_OFFSET   0x3

#define PAD_SIZE        0x25

#define CALL_SIZE       0x7

const BYTE MOV_STUB[] = {
    0x4C, 0x8B, 0xD1,               // mov r10, rcx
    0xB8, 0x18, 0x00, 0x00, 0x00    // mov eax, 0x18
};

BYTE PAD_BYTES[PAD_SIZE] = { 0 };

int main(void) {
    HMODULE hKernelBase = GetModuleHandleA("KernelBase.dll");
    if (hKernelBase == NULL) {
        printf("[-] GetModuleHandleA() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    PUINT_PTR pVirtualAlloc = (PUINT_PTR) GetProcAddress(hKernelBase, "VirtualAlloc");
    if (pVirtualAlloc == NULL) {
        printf("[-] GetProcAddress() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[+] KERNELBASE.DLL!VirtualAlloc: 0x%p\n", pVirtualAlloc);

    DWORD oldProt;
    if (!VirtualProtect(pVirtualAlloc, 1, PAGE_EXECUTE_READWRITE, &oldProt)) {
        printf("[-] VirtualProtect() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[*] Patching call to 'NtAllocateVirtualMemory'..\n");
    PBYTE pCallInst = (PBYTE) ((UINT_PTR) pVirtualAlloc + NTCALL_OFFSET);
    printf("[+] Call Address: 0x%p\n", pCallInst);
    DWORD ripOffset = (*(PDWORD) ((UINT_PTR) pCallInst + RIP_DS_OFFSET)) + CALL_SIZE;
    printf("[+] RIP Offset: 0x%08X\n", ripOffset);

    if (!VirtualProtect(pCallInst + ripOffset + CALL_SIZE, 1, PAGE_READWRITE, &oldProt)) {
        printf("[-] VirtualProtect() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    UINT_PTR ripValue = (UINT_PTR) ((UINT_PTR) pVirtualAlloc + NTCALL_OFFSET);
    memcpy(PAD_BYTES, pCallInst, sizeof(PAD_BYTES));

    printf("[+] Patched call address: 0x%08llx\n", (UINT_PTR) pCallInst + sizeof(MOV_STUB));
    memcpy(pCallInst + sizeof(MOV_STUB), &PAD_BYTES[1], sizeof(PAD_BYTES) - 1);


    memcpy(pCallInst, MOV_STUB, sizeof(MOV_STUB));

    // 0x6 is the size of the patched call instruction
    ripOffset -= sizeof(MOV_STUB) + (CALL_SIZE - 1);
    printf("[+] New RIP Offset: 0x%08X\n", ripOffset);

    *((PDWORD) ((UINT_PTR) pCallInst + sizeof(MOV_STUB) + 2)) = ripOffset;

    printf("[+] Successfully patched 'call ds:[&NtAllocateVirtualMemory]' at 0x%p\n", pCallInst);

    PBYTE pCallInstPtr = (PBYTE) ((UINT_PTR) pCallInst + sizeof(MOV_STUB) + 0x6 + ripOffset);
    printf("[*] Patching pointer to 'NtAllocateVirtualMemory' at 0x%p..\n", pCallInstPtr);

    UINT_PTR ptrVal = *(PUINT_PTR) pCallInstPtr;
    ptrVal += 18;
    *((PUINT_PTR) ((UINT_PTR) pCallInstPtr)) = ptrVal;

    printf("[+] Successfully patched pointer to 'NtAllocateVirtualMemory' at 0x%p\n", pCallInstPtr);
    printf("[+] New pointer value: 0x%08llX\n", ptrVal);

    printf("\n[*] Press ENTER to call VirtualAlloc()..\n");
    char c = getchar();

    LPVOID lpAddr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (NULL == lpAddr) {
        printf("[-] VirtualAlloc() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[+] VirtualAlloc() success - allocated 0x1000 bytes (RWX) at 0x%p\n", lpAddr);
    while (1);
    return EXIT_SUCCESS;
}
