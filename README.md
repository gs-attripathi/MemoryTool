# Memory Tool - Cheat Engine Alternative

A high-performance, terminal-based memory manipulation tool for Windows, similar to Cheat Engine. Built in C++ for maximum speed and efficiency.

## Features

### 🎯 Process Attachment
- Attach to processes by substring matching (e.g., "forza" matches "ForzaHorizon5.exe")
- Automatic process selection with PID display
- Full process memory access

### 🔍 Memory Value Search
- **Supported Data Types:**
  - Byte (1 byte)
  - 2-Byte (short/word)
  - 4-Byte (int/dword)
  - Float (4 bytes)
  - Double (8 bytes)
  - String (null-terminated)
  - Pointer (memory address)

- **Fast Memory Scanning:**
  - Optimized chunk-based reading (1MB chunks)
  - Multi-threaded scanning capability
  - Comprehensive memory region coverage

### ✏️ Value Modification
- **Python-style indexing:**
  - Single index: `5` (modify 5th result)
  - Range: `10:20` (modify results 10-19)
  - Open ranges: `:50` (first 50), `25:` (from 25 to end)
- Real-time memory writing
- Batch modification support

### 🔗 Pointer Search
- **Advanced Pointer Path Discovery:**
  - Configurable search depth (how many pointer levels)
  - Configurable offset range (max offset from base)
  - Static base resolution (DLL/EXE modules)
  - Interruptible searches (press 'q' to stop)

- **Pointer Path Format:**
  - `[[game.exe+0x544]+0x23]+0x32` (3-level pointer)
  - Human-readable explanations
  - Traceable from static addresses

- **Save/Resume Functionality:**
  - Save pointer scans to timestamped files
  - Human-readable format with explanations
  - Resume capability for long searches

## Building

### Requirements
- Windows 10/11
- One of the following compilers:
  - **Visual Studio Build Tools** (recommended)
  - **MinGW-w64**

### Method 1: Simple Build (Recommended)
```batch
# Run from Command Prompt or PowerShell
build_simple.bat
```

### Method 2: CMake Build
```batch
# For advanced users
build.bat
```

### Manual Compilation
```batch
# Visual Studio
cl /EHsc /O2 /MT memory_tool.cpp /link psapi.lib /out:MemoryTool.exe

# MinGW
g++ -std=c++17 -O3 -static memory_tool.cpp -lpsapi -o MemoryTool.exe
```

## Usage

### 1. Launch and Attach
```
Enter process name substring: forza
```
The tool will find and attach to processes containing "forza" (like ForzaHorizon5.exe).

### 2. Search for Values
```
=== Main Menu ===
1. Search for value in memory
```

**Example - Finding Health Value:**
```
Select data type: 4 (4-Byte integer)
Enter value to search for: 100
```

**Results Display:**
```
Index | Address          | Value
------|------------------|------------------
    0 | 0x00007FF812345678 | 4-BYTE: 100 (0x64)
    1 | 0x00007FF812346789 | 4-BYTE: 100 (0x64)
```

### 3. Modify Values
```
2. Modify found values
Enter index/range: 0        # Modify first result
Enter new value: 999
```

**Advanced Indexing:**
```
Enter index/range: 5:10     # Modify results 5-9
Enter index/range: :20      # Modify first 20 results
Enter index/range: 50:      # Modify from result 50 to end
```

### 4. Pointer Search
```
3. Search for pointers to address
Enter target address: 0x12345678
Enter maximum offset: 1000
Enter maximum pointer depth: 5
```

**Results:**
```
Index | Pointer Path | Final Address
------|--------------|---------------
    0 | [[game.exe+0x544]+0x23] | 0x12345678
    1 | [[ntdll.dll+0x1000]+0x50]+0x10] | 0x12345678
```

**How to Use Pointer Paths:**
```
Example: game.exe+0x544+0x23
1. Get base address of game.exe
2. Add 0x544 to get intermediate address
3. Read pointer value at that address
4. Add 0x23 to get final address
```

## Value Type Reference

### Numeric Types
- **BYTE**: `255` → displays as "BYTE: 255 (0xFF)"
- **2-BYTE**: `65535` → displays as "2-BYTE: 65535 (0xFFFF)"
- **4-BYTE**: `4294967295` → displays as "4-BYTE: 4294967295 (0xFFFFFFFF)"
- **FLOAT**: `3.14159` → displays as "FLOAT: 3.141590"
- **DOUBLE**: `3.141592653589793` → displays as "DOUBLE: 3.1415926536"

### Special Types
- **STRING**: `"Hello World"` → displays as "STRING: \"Hello World\""
- **POINTER**: `0x12345678` → displays as "POINTER: 0x12345678"

## Performance Tips

### Memory Search Optimization
- Use specific data types when possible
- Start with unique values to reduce result count
- Use string searches for text-based games

### Pointer Search Optimization
- Start with smaller offset ranges (100-500)
- Use depth 3-5 for most games
- Interrupt long searches and save progress
- Filter results by examining saved files

## File Outputs

### Pointer Scan Files
Format: `pointer_scan_ProcessName_Timestamp.txt`

Example content:
```
Pointer Scan Results
Process: ForzaHorizon5.exe
Total paths found: 15

Path 0: [[ForzaHorizon5.exe+0x2A4C8B0]+0x18] -> 0x12345678
  Explanation: Read pointer at ForzaHorizon5.exe + 0x2A4C8B0, then add 0x18 to reach final address

Path 1: [[ForzaHorizon5.exe+0x2A4C8B0]+0x20]+0x8] -> 0x12345678
  Explanation: Read pointer at ForzaHorizon5.exe + 0x2A4C8B0, then add 0x20, then add 0x8 to reach final address
```

## Troubleshooting

### Common Issues

**"Failed to open process"**
- Run as Administrator
- Ensure target process is running
- Check if process has anti-cheat protection

**"No processes found"**
- Check process name spelling
- Ensure process is actually running
- Try shorter substring (e.g., "forza" instead of "forzahorizon")

**"Search too slow"**
- Use more specific data types
- Search for unique values first
- Close unnecessary applications

### Performance Notes
- The tool uses optimized memory scanning (1MB chunks)
- Pointer searches can be CPU-intensive for deep levels
- Save pointer scans frequently for long searches
- Use interrupt feature ('q') to stop long operations

## Security Considerations
- Requires Administrator privileges for memory access
- Only works on processes you have permission to access
- Some games with anti-cheat may block memory access
- Use responsibly and respect game terms of service

## Technical Details
- Written in C++ for maximum performance
- Uses Windows API for direct memory access
- Static linking for portable executable
- No external dependencies required
- Optimized for x64 Windows systems