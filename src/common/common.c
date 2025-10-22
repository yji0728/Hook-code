/*
 * Common Functions Implementation
 * 
 * Implementation of shared utility functions used across
 * all injection techniques.
 * 
 * For EDR testing purposes only.
 */

#include "common.h"
#include <sys/stat.h>

/**
 * Find process ID by process name
 * 
 * @param processName Name of the process to find (e.g., "notepad.exe")
 * @return Process ID if found, 0 otherwise
 */
DWORD GetProcessIdByName(const char* processName) {
    if (!processName) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to create process snapshot");
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
    
    if (pid == 0) {
        LOG_ERROR("Process '%s' not found", processName);
    }
    
    return pid;
}

/**
 * Get a thread ID from a process
 * 
 * @param pid Process ID to get thread from
 * @return Thread ID if found, 0 otherwise
 */
DWORD GetThreadIdByProcessId(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to create thread snapshot");
        return 0;
    }
    
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    
    DWORD tid = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                tid = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    CloseHandle(hSnapshot);
    
    if (tid == 0) {
        LOG_ERROR("No threads found in process %d", pid);
    }
    
    return tid;
}

/**
 * Validate if data is a valid PE file
 * 
 * @param pFileData Pointer to file data
 * @param fileSize Size of the file data
 * @return TRUE if valid PE file, FALSE otherwise
 */
BOOL ValidatePEFile(BYTE* pFileData, DWORD fileSize) {
    if (!pFileData || fileSize < sizeof(IMAGE_DOS_HEADER)) {
        LOG_ERROR("Invalid file data or size too small");
        return FALSE;
    }

    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pFileData;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        LOG_ERROR("Invalid DOS signature (MZ)");
        return FALSE;
    }
    
    if ((DWORD)pDosHeader->e_lfanew >= fileSize - sizeof(IMAGE_NT_HEADERS)) {
        LOG_ERROR("Invalid PE header offset");
        return FALSE;
    }
    
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pFileData + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        LOG_ERROR("Invalid NT signature (PE)");
        return FALSE;
    }
    
    LOG_SUCCESS("Valid PE file detected");
    return TRUE;
}

/**
 * Check if a file exists
 * 
 * @param filePath Path to the file
 * @return TRUE if file exists, FALSE otherwise
 */
BOOL FileExists(const char* filePath) {
    if (!filePath) {
        return FALSE;
    }
    
    struct stat buffer;
    return (stat(filePath, &buffer) == 0);
}

/**
 * Read entire file into memory
 * 
 * @param filePath Path to the file to read
 * @param ppBuffer Pointer to receive allocated buffer (caller must free)
 * @return Size of file in bytes, 0 on error
 */
DWORD ReadFileToMemory(const char* filePath, BYTE** ppBuffer) {
    if (!filePath || !ppBuffer) {
        LOG_ERROR("Invalid parameters");
        return 0;
    }
    
    *ppBuffer = NULL;
    
    if (!FileExists(filePath)) {
        LOG_ERROR("File not found: %s", filePath);
        return 0;
    }
    
    HANDLE hFile = CreateFileA(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to open file: %s. Error code: %d", filePath, GetLastError());
        return 0;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        LOG_ERROR("Failed to get file size");
        CloseHandle(hFile);
        return 0;
    }
    
    *ppBuffer = (BYTE*)malloc(fileSize);
    if (!*ppBuffer) {
        LOG_ERROR("Failed to allocate memory for file (%d bytes)", fileSize);
        CloseHandle(hFile);
        return 0;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, *ppBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        LOG_ERROR("Failed to read file");
        free(*ppBuffer);
        *ppBuffer = NULL;
        CloseHandle(hFile);
        return 0;
    }
    
    CloseHandle(hFile);
    LOG_SUCCESS("File loaded into memory (%d bytes)", fileSize);
    return fileSize;
}

/**
 * Print usage information
 * 
 * @param programName Name of the program
 * @param usage Usage string
 * @param example Example usage string
 */
void PrintUsage(const char* programName, const char* usage, const char* example) {
    printf("Usage: %s %s\n", programName, usage);
    if (example) {
        printf("Example: %s %s\n", programName, example);
    }
}
