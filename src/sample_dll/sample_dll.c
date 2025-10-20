/*
 * Sample Test DLL for Injection Testing
 * 
 * This is a harmless DLL that can be used for testing injection techniques.
 * It simply displays a message box when loaded.
 * 
 * Build command:
 * cl.exe /LD /O2 /Fe:test_payload.dll sample_dll.c user32.lib
 * or
 * x86_64-w64-mingw32-gcc -shared -o test_payload.dll sample_dll.c -luser32
 */

#include <windows.h>
#include <stdio.h>

// DLL Entry Point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // DLL is being loaded into the process
            MessageBoxA(
                NULL,
                "Test DLL successfully injected!\nThis is a harmless test payload.",
                "Injection Test - Success",
                MB_OK | MB_ICONINFORMATION
            );
            
            // Optional: Create a log file
            FILE* logFile = fopen("C:\\injection_test_log.txt", "a");
            if (logFile) {
                SYSTEMTIME st;
                GetLocalTime(&st);
                fprintf(logFile, "[%04d-%02d-%02d %02d:%02d:%02d] DLL injected into process (PID: %d)\n",
                    st.wYear, st.wMonth, st.wDay,
                    st.wHour, st.wMinute, st.wSecond,
                    GetCurrentProcessId());
                fclose(logFile);
            }
            break;
            
        case DLL_PROCESS_DETACH:
            // DLL is being unloaded
            break;
            
        case DLL_THREAD_ATTACH:
            // A new thread is being created
            break;
            
        case DLL_THREAD_DETACH:
            // A thread is exiting cleanly
            break;
    }
    
    return TRUE;
}

// Exported function that can be called after injection
__declspec(dllexport) void TestFunction(void) {
    MessageBoxA(
        NULL,
        "TestFunction called successfully!",
        "Injection Test - Function Call",
        MB_OK | MB_ICONINFORMATION
    );
}
