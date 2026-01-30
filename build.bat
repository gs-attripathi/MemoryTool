@echo off
echo Building Memory Tool...

REM Check if Visual Studio Build Tools are available
where cl >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Using Visual Studio compiler...
    goto :build_msvc
)

REM Check if MinGW is available
where g++ >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Using MinGW compiler...
    goto :build_mingw
)

echo Error: No suitable compiler found. Please install either:
echo 1. Visual Studio Build Tools (recommended)
echo 2. MinGW-w64
echo.
echo For Visual Studio Build Tools, run this from "Developer Command Prompt"
pause
exit /b 1

:build_msvc
REM Create build directory
if not exist build mkdir build
cd build

REM Configure with CMake for Visual Studio
cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
if %ERRORLEVEL% NEQ 0 (
    echo CMake configuration failed!
    pause
    exit /b 1
)

REM Build the project
nmake
if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b 1
)

goto :success

:build_mingw
REM Create build directory
if not exist build mkdir build
cd build

REM Configure with CMake for MinGW
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
if %ERRORLEVEL% NEQ 0 (
    echo CMake configuration failed!
    pause
    exit /b 1
)

REM Build the project
mingw32-make
if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b 1
)

goto :success

:success
echo.
echo Build successful! 
echo Executable created: MemoryTool.exe
echo.
echo The executable is self-contained and requires no additional setup.
echo You can copy MemoryTool.exe to any Windows machine and run it directly.
echo.
pause