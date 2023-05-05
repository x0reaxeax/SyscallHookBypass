/// Winver: Win10 x64 21H2 19044.2846
/// KernelBase.dll ver: 10.0.19041.2788

#include <stdio.h>
#include <Windows.h>

#define SE_DEBUG_PRIVILEGE  (20)

#define NTCALL_OFFSET       0xB7
#define RIP_DS_OFFSET       0x03

#define PAD_SIZE            0x25

#define CALL_SIZE           0x07

const BYTE MOV_STUB[] = {
    0x4C, 0x8B, 0xD1,               // mov r10, rcx
    0xB8, 0x3a, 0x00, 0x00, 0x00    // mov eax, 0x3a
};

BYTE PAD_BYTES[PAD_SIZE] = { 0 };

int main(int argc, const char *argv[]) {
    
    if (argc < 3) {
        fprintf(
            stderr,
            "usage: %s <pid> <addy>\n",
            argv[0]
        );
        return EXIT_FAILURE;
    }
    
    DWORD dwPid = atoi(argv[1]);
    UINT_PTR uiAddress = strtoull(argv[2], NULL, 16);

    HMODULE hKernelBase = GetModuleHandleA("KernelBase.dll");
    if (hKernelBase == NULL) {
        printf("[-] GetModuleHandleA() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    PUINT_PTR pWriteProcessMemory = (PUINT_PTR) GetProcAddress(hKernelBase, "WriteProcessMemory");
    if (pWriteProcessMemory == NULL) {
        printf("[-] GetProcAddress() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[+] KERNELBASE.DLL!WriteProcessMemory: 0x%p\n", pWriteProcessMemory);

    DWORD oldProt;
    if (!VirtualProtect(pWriteProcessMemory, 1, PAGE_EXECUTE_READWRITE, &oldProt)) {
        printf("[-] VirtualProtect() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[*] Patching call to 'NtWriteVirtualMemory'..\n");
    PBYTE pCallInst = (PBYTE) ((UINT_PTR) pWriteProcessMemory + NTCALL_OFFSET);
    printf("[+] Call Address: 0x%p\n", pCallInst);
    DWORD ripOffset = (*(PDWORD) ((UINT_PTR) pCallInst + RIP_DS_OFFSET)) + CALL_SIZE;
    printf("[+] RIP Offset: 0x%08X\n", ripOffset);

    if (!VirtualProtect(pCallInst + ripOffset + CALL_SIZE, 1, PAGE_READWRITE, &oldProt)) {
        printf("[-] VirtualProtect() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    UINT_PTR ripValue = (UINT_PTR) ((UINT_PTR) pWriteProcessMemory + NTCALL_OFFSET);
    memcpy(PAD_BYTES, pCallInst, sizeof(PAD_BYTES));

    printf("[+] Patched call address: 0x%08llx\n", (UINT_PTR) pCallInst + sizeof(MOV_STUB));
    memcpy(pCallInst + sizeof(MOV_STUB), &PAD_BYTES[1], sizeof(PAD_BYTES) - 1);

    memcpy(pCallInst, MOV_STUB, sizeof(MOV_STUB));

    // 0x6 is the size of the patched call instruction
    ripOffset -= sizeof(MOV_STUB) + (CALL_SIZE - 1);
    printf("[+] New RIP Offset: 0x%08X\n", ripOffset);

    *((PDWORD) ((UINT_PTR) pCallInst + sizeof(MOV_STUB) + 2)) = ripOffset;

    printf("[+] Successfully patched 'call ds:[&NtWriteVirtualMemory]' at 0x%p\n", pCallInst);

    PBYTE pCallInstPtr = (PBYTE) ((UINT_PTR) pCallInst + sizeof(MOV_STUB) + 0x6 + ripOffset);
    printf("[*] Patching pointer to 'NtWriteVirtualMemory' at 0x%p..\n", pCallInstPtr);

    UINT_PTR ptrVal = *(PUINT_PTR) pCallInstPtr;
    ptrVal += 18;
    *((PUINT_PTR) ((UINT_PTR) pCallInstPtr)) = ptrVal;

    printf("[+] Successfully patched pointer to 'NtWriteVirtualMemory' at 0x%p\n", pCallInstPtr);
    printf("[+] New pointer value: 0x%08llX\n", ptrVal);

    printf("\n[*] Press ENTER to call WriteProcessMemory()..\n");
    char c = getchar();

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE,
        FALSE,
        dwPid
    );

    if (NULL == hProcess) {
        printf("[-] OpenProcess() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    CONST CHAR szBuf[] = "Hello, World!\n";

    if (!WriteProcessMemory(
        hProcess,
        (LPVOID) uiAddress,
        szBuf,
        sizeof(szBuf),
        NULL
    )) {
        fprintf(
            stderr,
            "[-] WriteProcessMemory() failed: %lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    printf("[+] WriteProcessMemory() success\n");

    while (1);

    return EXIT_SUCCESS;
}
