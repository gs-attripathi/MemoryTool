@echo off
echo Building test target...

REM Check for MinGW
where g++ >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Compiling test target with MinGW...
    g++ -std=c++17 -O0 test_target.cpp -o test_target.exe
    if %ERRORLEVEL% EQU 0 (
        echo Test target built successfully!
        echo Run test_target.exe in one window, then use MemoryTool.exe in another
    ) else (
        echo Build failed!
    )
    goto :end
)

REM Check for Visual Studio
where cl >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Compiling test target with Visual Studio...
    cl /EHsc test_target.cpp /out:test_target.exe
    if %ERRORLEVEL% EQU 0 (
        echo Test target built successfully!
        echo Run test_target.exe in one window, then use MemoryTool.exe in another
    ) else (
        echo Build failed!
    )
    goto :end
)

echo No compiler found!

:end
pause