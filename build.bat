@echo off
REM ============================================================================
REM  PackerZero v1.0 - stub builder
REM  Builds stub_exe.exe (packs EXEs) and stub_dll.dll (packs DLLs).
REM  Requires either MSVC (cl.exe) or MinGW-w64 (x86_64-w64-mingw32-gcc).
REM  No network access. No execution of packed output. Build only.
REM ============================================================================
setlocal
cd /d "%~dp0"

where cl >nul 2>nul && goto msvc
where x86_64-w64-mingw32-gcc >nul 2>nul && goto mingw
where gcc >nul 2>nul && goto mingw-native

echo [!] No C compiler found.
echo     Install one of:
echo       - MSVC Build Tools (https://visualstudio.microsoft.com/build-tools/)
echo         then run from a "x64 Native Tools Command Prompt"
echo       - MinGW-w64 (https://www.mingw-w64.org/) with x86_64-...-gcc on PATH
echo.
echo     After installing, re-run build.bat, or build manually:
echo       see README.md "Building the stub" section.
exit /b 1

:msvc
echo [*] Building with MSVC...
cl /nologo /O2 /GS- /Gy /NODEFAULTLIB /entry:StubEntry /link /SUBSYSTEM:WINDOWS /NODEFAULTLIB kernel32.lib bcrypt.lib /OUT:stub\stub_exe.exe stub\stub.c
if errorlevel 1 goto fail
cl /nologo /O2 /GS- /Gy /NODEFAULTLIB /DSTUB_DLL /entry:DllMainStub /link /SUBSYSTEM:WINDOWS /DLL /NODEFAULTLIB kernel32.lib bcrypt.lib /OUT:stub\stub_dll.dll stub\stub.c
if errorlevel 1 goto fail
goto done

:mingw
echo [*] Building with MinGW-w64...
x86_64-w64-mingw32-gcc -O2 -nostdlib -fno-stack-protector -o stub\stub_exe.exe stub\stub.c -Wl,--entry=StubEntry -lkernel32 -lbcrypt -lgcc
if errorlevel 1 goto fail
x86_64-w64-mingw32-gcc -O2 -nostdlib -fno-stack-protector -shared -DSTUB_DLL -o stub\stub_dll.dll stub\stub.c -Wl,--entry=DllMainStub -lkernel32 -lbcrypt -lgcc
if errorlevel 1 goto fail
goto done

:mingw-native
echo [*] Building with native gcc (MinGW-w64 on PATH as gcc)...
gcc -O2 -nostdlib -fno-stack-protector -o stub\stub_exe.exe stub\stub.c -Wl,--entry=StubEntry -lkernel32 -lbcrypt -lgcc
if errorlevel 1 goto fail
gcc -O2 -nostdlib -fno-stack-protector -shared -DSTUB_DLL -o stub\stub_dll.dll stub\stub.c -Wl,--entry=DllMainStub -lkernel32 -lbcrypt -lgcc
if errorlevel 1 goto fail
goto done

:fail
echo [!] Build FAILED.
exit /b 1

:done
echo [+] stub\stub_exe.exe and stub\stub_dll.dll built.
echo [*] Run "python packer.py selftest" to validate the packer side.
endlocal
