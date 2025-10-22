/*
 * Common Header for Process Injection Techniques
 * 
 * This header provides common functions and macros used across
 * all injection techniques to reduce code duplication and
 * improve maintainability.
 * 
 * For EDR testing purposes only.
 */

#ifndef COMMON_H
#define COMMON_H

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Color codes for console output (if needed)
#define COLOR_RESET   ""
#define COLOR_RED     ""
#define COLOR_GREEN   ""
#define COLOR_YELLOW  ""
#define COLOR_BLUE    ""

// Logging macros
#define LOG_INFO(fmt, ...)    printf("[*] " fmt "\n", ##__VA_ARGS__)
#define LOG_SUCCESS(fmt, ...) printf("[+] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)   printf("[!] Error: " fmt "\n", ##__VA_ARGS__)
#define LOG_WARNING(fmt, ...) printf("[!] Warning: " fmt "\n", ##__VA_ARGS__)

// Error handling macros
#define CHECK_HANDLE(handle, msg) \
    do { \
        if ((handle) == NULL || (handle) == INVALID_HANDLE_VALUE) { \
            LOG_ERROR("%s. Error code: %d", (msg), GetLastError()); \
            goto cleanup; \
        } \
    } while(0)

#define CHECK_BOOL(condition, msg) \
    do { \
        if (!(condition)) { \
            LOG_ERROR("%s. Error code: %d", (msg), GetLastError()); \
            goto cleanup; \
        } \
    } while(0)

#define SAFE_CLOSE_HANDLE(handle) \
    do { \
        if ((handle) != NULL && (handle) != INVALID_HANDLE_VALUE) { \
            CloseHandle(handle); \
            (handle) = NULL; \
        } \
    } while(0)

#define SAFE_FREE(ptr) \
    do { \
        if ((ptr) != NULL) { \
            free(ptr); \
            (ptr) = NULL; \
        } \
    } while(0)

// Function prototypes
DWORD GetProcessIdByName(const char* processName);
DWORD GetThreadIdByProcessId(DWORD pid);
BOOL ValidatePEFile(BYTE* pFileData, DWORD fileSize);
BOOL FileExists(const char* filePath);
DWORD ReadFileToMemory(const char* filePath, BYTE** ppBuffer);
void PrintUsage(const char* programName, const char* usage, const char* example);

// Inline helper functions
static inline BOOL IsValidHandle(HANDLE handle) {
    return (handle != NULL && handle != INVALID_HANDLE_VALUE);
}

static inline void SafeCloseHandle(HANDLE* pHandle) {
    if (pHandle && IsValidHandle(*pHandle)) {
        CloseHandle(*pHandle);
        *pHandle = NULL;
    }
}

#endif // COMMON_H
