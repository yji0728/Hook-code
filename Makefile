# Makefile for Windows Process Injection Techniques
# Supports both MSVC (Windows) and MinGW (cross-compile from Linux)

# Detect the compiler
ifeq ($(OS),Windows_NT)
    # Windows with MSVC
    CC = cl.exe
    CFLAGS = /W3 /O2 /I"src"
    LDFLAGS = /link /SUBSYSTEM:CONSOLE
    OUT_FLAG = /Fe:
    EXE_EXT = .exe
    RM = del /Q
    MKDIR = if not exist
else
    # Linux with MinGW cross-compiler
    CC = x86_64-w64-mingw32-gcc
    CFLAGS = -O2 -Wall -Isrc
    LDFLAGS = 
    OUT_FLAG = -o 
    EXE_EXT = .exe
    RM = rm -f
    MKDIR = mkdir -p
endif

# Output directory
BIN_DIR = bin

# Common files
SRC_COMMON = src/common/common.c

# Source files
SRC_01 = src/01_classic_dll_injection/injector.c
SRC_02 = src/02_process_hollowing/hollowing.c
SRC_03 = src/03_apc_injection/apc_injector.c
SRC_04 = src/04_thread_hijacking/hijack_thread.c
SRC_05 = src/05_reflective_dll_injection/reflective_loader_fixed.c
SRC_DLL = src/sample_dll/sample_dll.c

# Target executables
TARGET_01 = $(BIN_DIR)/01_classic_dll_injection$(EXE_EXT)
TARGET_02 = $(BIN_DIR)/02_process_hollowing$(EXE_EXT)
TARGET_03 = $(BIN_DIR)/03_apc_injection$(EXE_EXT)
TARGET_04 = $(BIN_DIR)/04_thread_hijacking$(EXE_EXT)
TARGET_05 = $(BIN_DIR)/05_reflective_dll_injection$(EXE_EXT)
TARGET_DLL = $(BIN_DIR)/test_payload.dll

# All targets
TARGETS = $(TARGET_01) $(TARGET_02) $(TARGET_03) $(TARGET_04) $(TARGET_05) $(TARGET_DLL)

# Default target
all: $(BIN_DIR) $(TARGETS)
	@echo.
	@echo Build completed successfully!
	@echo Binaries are located in the '$(BIN_DIR)' directory.

# Create output directory
$(BIN_DIR):
	$(MKDIR) $(BIN_DIR)

# Build individual targets (MinGW style)
ifeq ($(CC),x86_64-w64-mingw32-gcc)
$(TARGET_01): $(SRC_01) $(SRC_COMMON)
	@echo [1/6] Building Classic DLL Injection...
	$(CC) $(CFLAGS) $(OUT_FLAG)$@ $^ $(LDFLAGS)

$(TARGET_02): $(SRC_02) $(SRC_COMMON)
	@echo [2/6] Building Process Hollowing...
	$(CC) $(CFLAGS) $(OUT_FLAG)$@ $^ $(LDFLAGS)

$(TARGET_03): $(SRC_03) $(SRC_COMMON)
	@echo [3/6] Building APC Injection...
	$(CC) $(CFLAGS) $(OUT_FLAG)$@ $^ $(LDFLAGS)

$(TARGET_04): $(SRC_04) $(SRC_COMMON)
	@echo [4/6] Building Thread Hijacking...
	$(CC) $(CFLAGS) $(OUT_FLAG)$@ $^ $(LDFLAGS)

$(TARGET_05): $(SRC_05) $(SRC_COMMON)
	@echo [5/6] Building Reflective DLL Injection...
	$(CC) $(CFLAGS) $(OUT_FLAG)$@ $^ $(LDFLAGS)

$(TARGET_DLL): $(SRC_DLL)
	@echo [6/6] Building Test Payload DLL...
	$(CC) $(CFLAGS) -shared $(OUT_FLAG)$@ $< -luser32
else
# Build individual targets (MSVC style)
$(TARGET_01): $(SRC_01) $(SRC_COMMON)
	@echo [1/6] Building Classic DLL Injection...
	$(CC) $(CFLAGS) $(OUT_FLAG)$@ $^ $(LDFLAGS)

$(TARGET_02): $(SRC_02) $(SRC_COMMON)
	@echo [2/6] Building Process Hollowing...
	$(CC) $(CFLAGS) $(OUT_FLAG)$@ $^ $(LDFLAGS)

$(TARGET_03): $(SRC_03) $(SRC_COMMON)
	@echo [3/6] Building APC Injection...
	$(CC) $(CFLAGS) $(OUT_FLAG)$@ $^ $(LDFLAGS)

$(TARGET_04): $(SRC_04) $(SRC_COMMON)
	@echo [4/6] Building Thread Hijacking...
	$(CC) $(CFLAGS) $(OUT_FLAG)$@ $^ $(LDFLAGS)

$(TARGET_05): $(SRC_05) $(SRC_COMMON)
	@echo [5/6] Building Reflective DLL Injection...
	$(CC) $(CFLAGS) $(OUT_FLAG)$@ $< $(LDFLAGS)

$(TARGET_DLL): $(SRC_DLL)
	@echo [6/6] Building Test Payload DLL...
	$(CC) /LD $(CFLAGS) $(OUT_FLAG)$@ $< user32.lib
endif

# Clean build artifacts
clean:
ifeq ($(OS),Windows_NT)
	$(RM) $(BIN_DIR)\*.exe $(BIN_DIR)\*.dll 2>nul
	$(RM) *.obj *.lib *.exp 2>nul
else
	$(RM) $(BIN_DIR)/*.exe $(BIN_DIR)/*.dll
	$(RM) *.o
endif
	@echo Clean completed.

# Help target
help:
	@echo Windows Process Injection Techniques - Makefile
	@echo.
	@echo Available targets:
	@echo   all     - Build all injection tools (default)
	@echo   clean   - Remove all build artifacts
	@echo   help    - Display this help message
	@echo.
	@echo Individual targets:
	@echo   $(TARGET_01)
	@echo   $(TARGET_02)
	@echo   $(TARGET_03)
	@echo   $(TARGET_04)
	@echo   $(TARGET_05)
	@echo   $(TARGET_DLL)

.PHONY: all clean help
