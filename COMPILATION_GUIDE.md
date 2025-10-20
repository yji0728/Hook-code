# Compilation Guide - 컴파일 가이드

## 빌드 환경 요구사항 (Build Environment Requirements)

### Windows

#### Visual Studio (권장)
- Visual Studio 2019 이상
- 또는 Visual Studio Build Tools
- Windows SDK 포함

#### MinGW (대안)
- MinGW-w64
- GCC 7.0 이상

### Linux (Cross-Compilation)

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install mingw-w64

# Fedora/RHEL
sudo dnf install mingw64-gcc

# Arch Linux
sudo pacman -S mingw-w64-gcc
```

---

## 빌드 방법 (Build Methods)

### 방법 1: 자동 빌드 스크립트 사용

#### Windows
```batch
# Visual Studio Developer Command Prompt에서 실행
build.bat
```

#### Linux
```bash
chmod +x build.sh
./build.sh
```

### 방법 2: Makefile 사용

#### Windows (NMAKE)
```batch
nmake /f Makefile
```

#### Linux/macOS (GNU Make)
```bash
make
```

#### 개별 타겟 빌드
```bash
make bin/01_classic_dll_injection.exe
```

#### 정리
```bash
make clean
```

### 방법 3: 수동 컴파일

#### Windows - MSVC

```batch
# 1. Classic DLL Injection
cl.exe /W3 /O2 /Fe:bin\01_classic_dll_injection.exe ^
  src\01_classic_dll_injection\injector.c /link /SUBSYSTEM:CONSOLE

# 2. Process Hollowing
cl.exe /W3 /O2 /Fe:bin\02_process_hollowing.exe ^
  src\02_process_hollowing\hollowing.c /link /SUBSYSTEM:CONSOLE

# 3. APC Injection
cl.exe /W3 /O2 /Fe:bin\03_apc_injection.exe ^
  src\03_apc_injection\apc_injector.c /link /SUBSYSTEM:CONSOLE

# 4. Thread Hijacking
cl.exe /W3 /O2 /Fe:bin\04_thread_hijacking.exe ^
  src\04_thread_hijacking\hijack_thread.c /link /SUBSYSTEM:CONSOLE

# 5. Reflective DLL Injection
cl.exe /W3 /O2 /Fe:bin\05_reflective_dll_injection.exe ^
  src\05_reflective_dll_injection\reflective_loader.c /link /SUBSYSTEM:CONSOLE

# Sample Test DLL
cl.exe /LD /O2 /Fe:bin\test_payload.dll ^
  src\sample_dll\sample_dll.c user32.lib
```

#### Windows - MinGW / Linux Cross-Compile

```bash
# 1. Classic DLL Injection
x86_64-w64-mingw32-gcc -O2 -Wall \
  -o bin/01_classic_dll_injection.exe \
  src/01_classic_dll_injection/injector.c

# 2. Process Hollowing
x86_64-w64-mingw32-gcc -O2 -Wall \
  -o bin/02_process_hollowing.exe \
  src/02_process_hollowing/hollowing.c

# 3. APC Injection
x86_64-w64-mingw32-gcc -O2 -Wall \
  -o bin/03_apc_injection.exe \
  src/03_apc_injection/apc_injector.c

# 4. Thread Hijacking
x86_64-w64-mingw32-gcc -O2 -Wall \
  -o bin/04_thread_hijacking.exe \
  src/04_thread_hijacking/hijack_thread.c

# 5. Reflective DLL Injection
x86_64-w64-mingw32-gcc -O2 -Wall \
  -o bin/05_reflective_dll_injection.exe \
  src/05_reflective_dll_injection/reflective_loader.c

# Sample Test DLL
x86_64-w64-mingw32-gcc -O2 -Wall -shared \
  -o bin/test_payload.dll \
  src/sample_dll/sample_dll.c -luser32
```

---

## 컴파일 옵션 설명 (Compiler Options)

### MSVC 옵션

| 옵션 | 설명 |
|------|------|
| `/W3` | Warning level 3 (권장) |
| `/O2` | 최대 속도 최적화 |
| `/Fe:` | 출력 파일 이름 지정 |
| `/LD` | DLL 생성 |
| `/link` | 링커 옵션 시작 |
| `/SUBSYSTEM:CONSOLE` | 콘솔 애플리케이션 |

### GCC/MinGW 옵션

| 옵션 | 설명 |
|------|------|
| `-O2` | 최적화 레벨 2 |
| `-Wall` | 모든 경고 표시 |
| `-o` | 출력 파일 이름 지정 |
| `-shared` | 공유 라이브러리(DLL) 생성 |
| `-l` | 라이브러리 링크 |
| `-m32` | 32비트 바이너리 생성 |

---

## 아키텍처별 빌드 (Architecture-Specific Builds)

### 64비트 빌드 (기본)

```batch
# MSVC
cl.exe /O2 src\example.c

# MinGW
x86_64-w64-mingw32-gcc -O2 src/example.c
```

### 32비트 빌드

```batch
# MSVC (x86 Developer Command Prompt 사용)
cl.exe /O2 src\example.c

# MinGW
i686-w64-mingw32-gcc -O2 src/example.c
# or
x86_64-w64-mingw32-gcc -m32 -O2 src/example.c
```

---

## 빌드 출력 (Build Output)

성공적인 빌드 후 다음 파일들이 생성됩니다:

```
bin/
├── 01_classic_dll_injection.exe       (~50 KB)
├── 02_process_hollowing.exe           (~60 KB)
├── 03_apc_injection.exe               (~45 KB)
├── 04_thread_hijacking.exe            (~48 KB)
├── 05_reflective_dll_injection.exe    (~55 KB)
└── test_payload.dll                   (~20 KB)
```

---

## 디버그 빌드 (Debug Builds)

### MSVC Debug Build

```batch
cl.exe /Zi /Od /Fe:bin\injector_debug.exe ^
  src\01_classic_dll_injection\injector.c ^
  /link /DEBUG /SUBSYSTEM:CONSOLE
```

옵션 설명:
- `/Zi`: 디버그 정보 생성
- `/Od`: 최적화 비활성화
- `/DEBUG`: 디버그 정보 포함

### MinGW Debug Build

```bash
x86_64-w64-mingw32-gcc -g -O0 -Wall \
  -o bin/injector_debug.exe \
  src/01_classic_dll_injection/injector.c
```

옵션 설명:
- `-g`: 디버그 심볼 포함
- `-O0`: 최적화 비활성화

---

## 빌드 문제 해결 (Build Troubleshooting)

### 문제 1: "cl.exe를 찾을 수 없습니다"

**해결:**
```batch
# Visual Studio Developer Command Prompt 사용
# 또는
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
```

### 문제 2: "windows.h를 찾을 수 없습니다"

**해결:**
- Windows SDK가 설치되어 있는지 확인
- Visual Studio Installer에서 Windows SDK 설치

### 문제 3: MinGW 헤더 파일 누락

**해결:**
```bash
# Ubuntu/Debian
sudo apt-get install mingw-w64-dev

# 또는 전체 재설치
sudo apt-get install --reinstall mingw-w64
```

### 문제 4: 링크 오류 (Unresolved External Symbol)

**해결:**
```batch
# 필요한 라이브러리 추가
# MSVC
cl.exe ... user32.lib kernel32.lib

# MinGW
gcc ... -luser32 -lkernel32
```

### 문제 5: 아키텍처 불일치

**에러:** "LNK1112: module machine type 'x64' conflicts with target machine type 'x86'"

**해결:**
- 올바른 Developer Command Prompt 사용 (x86 vs x64)
- 또는 올바른 MinGW 컴파일러 사용 (i686 vs x86_64)

---

## 고급 빌드 옵션 (Advanced Build Options)

### 정적 링크

```batch
# MSVC
cl.exe /MT src\example.c

# MinGW
gcc -static src/example.c
```

### 최소 크기 빌드

```batch
# MSVC
cl.exe /O1 /Os src\example.c

# MinGW
gcc -Os -s src/example.c
```
- `/O1`, `-Os`: 크기 최적화
- `-s`: 심볼 제거 (strip)

### 코드 보안 강화

```batch
# MSVC
cl.exe /GS /sdl src\example.c

# MinGW
gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 src/example.c
```

---

## CI/CD 통합 (CI/CD Integration)

### GitHub Actions 예시

```yaml
name: Build

on: [push, pull_request]

jobs:
  build-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup MSVC
        uses: ilammy/msvc-dev-cmd@v1
      - name: Build
        run: build.bat

  build-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install MinGW
        run: sudo apt-get install mingw-w64
      - name: Build
        run: ./build.sh
```

---

## 빌드 검증 (Build Verification)

### 바이너리 정보 확인

```bash
# Linux
file bin/01_classic_dll_injection.exe

# Windows
dumpbin /headers bin\01_classic_dll_injection.exe
```

### 의존성 확인

```bash
# Linux
x86_64-w64-mingw32-objdump -p bin/01_classic_dll_injection.exe | grep "DLL Name"

# Windows
dumpbin /dependents bin\01_classic_dll_injection.exe
```

### 심볼 테이블 확인

```bash
# Linux
x86_64-w64-mingw32-nm bin/01_classic_dll_injection.exe

# Windows
dumpbin /symbols bin\01_classic_dll_injection.exe
```

---

## 추가 참고 자료 (Additional References)

- [MSVC Compiler Options](https://docs.microsoft.com/en-us/cpp/build/reference/compiler-options)
- [GCC Compiler Options](https://gcc.gnu.org/onlinedocs/gcc/Option-Summary.html)
- [MinGW-w64 Documentation](https://www.mingw-w64.org/)
- [CMake Documentation](https://cmake.org/documentation/)
