@echo off
echo Simple build without CMake...

REM Check for Visual Studio compiler
where cl >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Compiling with Visual Studio...
    cl /EHsc /O2 /MT memory_tool.cpp /link psapi.lib /out:MemoryTool.exe
    if %ERRORLEVEL% EQU 0 (
        echo Build successful! Created MemoryTool.exe
    ) else (
        echo Build failed!
    )
    goto :end
)

REM Check for MinGW
where g++ >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Compiling with MinGW...
    g++ -std=c++17 -O3 -static-libgcc -static-libstdc++ -static memory_tool.cpp -lpsapi -o MemoryTool.exe
    if %ERRORLEVEL% EQU 0 (
        echo Build successful! Created MemoryTool.exe
    ) else (
        echo Build failed!
    )
    goto :end
)

echo Error: No compiler found. Install Visual Studio Build Tools or MinGW.

:end
pause