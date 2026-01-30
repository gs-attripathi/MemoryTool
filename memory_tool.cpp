#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <map>
#include <set>
#include <conio.h>
#include <cmath>
#include <cstdint>

#pragma comment(lib, "psapi.lib")

// Data type enumeration
enum DataType {
    TYPE_BYTE = 1,
    TYPE_2BYTE,
    TYPE_4BYTE,
    TYPE_FLOAT,
    TYPE_DOUBLE,
    TYPE_STRING,
    TYPE_POINTER
};

// Structure to hold memory search results
struct MemoryResult {
    DWORD_PTR address;
    std::vector<BYTE> value;
    DataType type;
    size_t size;
};

// Structure for pointer search results
struct PointerPath {
    std::string baseName;
    DWORD_PTR baseAddress;
    std::vector<DWORD> offsets;
    DWORD_PTR finalAddress;
    DWORD_PTR originalTarget;  // The actual target we're looking for
    int finalOffset;           // Additional offset to reach original target
    int depth;
};

// Thread data structure for Windows native threading
struct ThreadData {
    class MemoryTool* memoryTool;
    std::map<DWORD_PTR, std::vector<DWORD_PTR>>* pointerMap;
    const std::vector<std::pair<DWORD_PTR, SIZE_T>>* regions;
    size_t startIdx;
    size_t endIdx;
};

// Structure scan thread data
struct StructureScanData {
    DWORD_PTR targetAddr;
    const std::map<DWORD_PTR, std::vector<DWORD_PTR>>* pointerMap;
    std::vector<std::pair<DWORD_PTR, int>>* results;
    int startOffset;
    int endOffset;
    class MemoryTool* memoryTool;
    volatile LONG processed;
};

// Forward declarations for thread procedures
DWORD WINAPI ScanRegionsThreadProc(LPVOID lpParam);
DWORD WINAPI StructureScanThreadProc(LPVOID lpParam);

class MemoryTool {
private:
    HANDLE processHandle;
    DWORD processId;
    std::string processName;
    std::vector<MemoryResult> searchResults;
    std::vector<PointerPath> pointerResults;
    std::map<std::string, DWORD_PTR> moduleMap;

    // Target architecture info
    bool targetIs64Bit;
    size_t targetPointerSize;
    DWORD_PTR targetPointerAlignment;
    uint64_t targetMaxUserAddress;
    
    // Progress tracking for in-place logging
    std::string currentScanType;
    int currentProgress;
    int totalProgress;
    
    // Windows native threading for MinGW compatibility
    CRITICAL_SECTION pointerMapCriticalSection;
    CRITICAL_SECTION counterCriticalSection;
    volatile LONG regionsProcessed;
    volatile LONG totalPointersFound;
    bool criticalSectionInitialized;

public:
    // Public accessor for thread safety
    volatile bool interruptSearch;

    MemoryTool() : processHandle(NULL), processId(0), interruptSearch(false), 
                   targetIs64Bit(false), targetPointerSize(sizeof(DWORD_PTR)),
                   targetPointerAlignment(4), targetMaxUserAddress(0x7FFFFFFFULL),
                   regionsProcessed(0), totalPointersFound(0), criticalSectionInitialized(false) {
        InitializeCriticalSection(&pointerMapCriticalSection);
        InitializeCriticalSection(&counterCriticalSection);
        criticalSectionInitialized = true;
    }
    
    ~MemoryTool() {
        if (processHandle) {
            CloseHandle(processHandle);
        }
        if (criticalSectionInitialized) {
            DeleteCriticalSection(&pointerMapCriticalSection);
            DeleteCriticalSection(&counterCriticalSection);
        }
    }

    // Find and attach to process by substring
    bool AttachToProcess(const std::string& processSubstring) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            std::cout << "Failed to create process snapshot\n";
            return false;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        std::vector<std::pair<DWORD, std::string>> matchingProcesses;

        if (Process32First(snapshot, &pe32)) {
            do {
                std::string procName = pe32.szExeFile;
                std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
                std::string searchStr = processSubstring;
                std::transform(searchStr.begin(), searchStr.end(), searchStr.begin(), ::tolower);
                
                if (procName.find(searchStr) != std::string::npos) {
                    matchingProcesses.push_back({pe32.th32ProcessID, pe32.szExeFile});
                }
            } while (Process32Next(snapshot, &pe32));
        }

        CloseHandle(snapshot);

        if (matchingProcesses.empty()) {
            std::cout << "No processes found containing: " << processSubstring << std::endl;
            return false;
        }

        if (matchingProcesses.size() > 1) {
            std::cout << "Multiple processes found:\n";
            for (size_t i = 0; i < matchingProcesses.size(); i++) {
                std::cout << i + 1 << ": " << matchingProcesses[i].second 
                         << " (PID: " << matchingProcesses[i].first << ")\n";
            }
            
            int choice;
            std::cout << "Select process (1-" << matchingProcesses.size() << "): ";
            std::cin >> choice;
            
            if (choice < 1 || choice > (int)matchingProcesses.size()) {
                std::cout << "Invalid selection\n";
                return false;
            }
            
            processId = matchingProcesses[choice - 1].first;
            processName = matchingProcesses[choice - 1].second;
        } else {
            processId = matchingProcesses[0].first;
            processName = matchingProcesses[0].second;
        }

        processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!processHandle) {
            std::cout << "Failed to open process. Error: " << GetLastError() << std::endl;
            return false;
        }

        InitializeTargetArchitecture();
        LoadModules();
        std::cout << "Successfully attached to: " << processName 
                 << " (PID: " << processId << " - 0x" << std::hex << processId << std::dec << ")\n";
        return true;
    }

    // Determine target process architecture for correct pointer size
    void InitializeTargetArchitecture() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        bool isOS64Bit = (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                          sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64);

        BOOL isWow64 = FALSE;
        if (isOS64Bit) {
            // Use dynamic lookup for IsWow64Process to support older MinGW headers
            typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
            LPFN_ISWOW64PROCESS fnIsWow64Process =
                (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");
            if (fnIsWow64Process) {
                fnIsWow64Process(processHandle, &isWow64);
            }
            targetIs64Bit = !isWow64; // if not WOW64, target is 64-bit
        } else {
            targetIs64Bit = false;
        }

        if (targetIs64Bit) {
            targetPointerSize = 8;
            targetPointerAlignment = 8;
            targetMaxUserAddress = 0x00007FFFFFFFFFFFULL;
        } else {
            targetPointerSize = 4;
            targetPointerAlignment = 4;
            targetMaxUserAddress = 0xFFFFFFFFULL;
        }

        std::cout << "Target architecture: " << (targetIs64Bit ? "64-bit" : "32-bit")
                  << " (pointer size: " << targetPointerSize << " bytes)\n";
    }

    // Load process modules for pointer base resolution
    void LoadModules() {
        moduleMap.clear();
        HMODULE modules[1024];
        DWORD needed;
        
        if (EnumProcessModules(processHandle, modules, sizeof(modules), &needed)) {
            for (unsigned int i = 0; i < (needed / sizeof(HMODULE)); i++) {
                char moduleName[MAX_PATH];
                if (GetModuleFileNameExA(processHandle, modules[i], moduleName, sizeof(moduleName))) {
                    std::string name = moduleName;
                    size_t pos = name.find_last_of("\\/");
                    if (pos != std::string::npos) {
                        name = name.substr(pos + 1);
                    }
                    moduleMap[name] = (DWORD_PTR)modules[i];
                }
            }
        }
    }

    // Convert string to bytes based on data type
    std::vector<BYTE> StringToBytes(const std::string& value, DataType type) {
        std::vector<BYTE> bytes;
        
        switch (type) {
            case TYPE_BYTE: {
                BYTE val = (BYTE)std::stoi(value);
                bytes.push_back(val);
                break;
            }
            case TYPE_2BYTE: {
                WORD val = (WORD)std::stoi(value);
                bytes.resize(2);
                memcpy(bytes.data(), &val, 2);
                break;
            }
            case TYPE_4BYTE: {
                DWORD val = (DWORD)std::stoul(value);
                bytes.resize(4);
                memcpy(bytes.data(), &val, 4);
                break;
            }
            case TYPE_FLOAT: {
                float val = std::stof(value);
                bytes.resize(4);
                memcpy(bytes.data(), &val, 4);
                break;
            }
            case TYPE_DOUBLE: {
                double val = std::stod(value);
                bytes.resize(8);
                memcpy(bytes.data(), &val, 8);
                break;
            }
            case TYPE_STRING: {
                bytes.assign(value.begin(), value.end());
                bytes.push_back(0); // null terminator
                break;
            }
            case TYPE_POINTER: {
                unsigned long long val = std::stoull(value, nullptr, 16);
                bytes.resize(targetPointerSize);
                if (targetPointerSize == 4) {
                    uint32_t v32 = static_cast<uint32_t>(val);
                    memcpy(bytes.data(), &v32, 4);
                } else {
                    uint64_t v64 = static_cast<uint64_t>(val);
                    memcpy(bytes.data(), &v64, 8);
                }
                break;
            }
        }
        
        return bytes;
    }

    // Fuzzy matching for float values
    bool IsFloatFuzzyMatch(float searchValue, float memoryValue) {
        // Handle exact matches first
        if (searchValue == memoryValue) return true;
        
        // Check if search value is integer-like (e.g., 681.0)
        if (searchValue == (float)(int)searchValue) {
            // If searching for "681", match 681.xxx
            return (int)searchValue == (int)memoryValue;
        }
        
        // For decimal searches (e.g., 681.2), use precision-based matching
        // Count decimal places in search value to determine tolerance
        std::string searchStr = std::to_string(searchValue);
        size_t decimalPos = searchStr.find('.');
        if (decimalPos != std::string::npos) {
            // Remove trailing zeros
            while (searchStr.back() == '0') searchStr.pop_back();
            if (searchStr.back() == '.') searchStr.pop_back();
            
            int decimalPlaces = searchStr.length() - decimalPos - 1;
            if (decimalPlaces > 0) {
                float tolerance = std::pow(10.0f, -(float)decimalPlaces) * 0.5f;
                return std::abs(searchValue - memoryValue) <= tolerance;
            }
        }
        
        // Default tolerance for edge cases
        return std::abs(searchValue - memoryValue) <= 0.001f;
    }

    // Fuzzy matching for double values
    bool IsDoubleFuzzyMatch(double searchValue, double memoryValue) {
        // Handle exact matches first
        if (searchValue == memoryValue) return true;
        
        // Check if search value is integer-like (e.g., 681.0)
        if (searchValue == (double)(long long)searchValue) {
            // If searching for "681", match 681.xxx
            return (long long)searchValue == (long long)memoryValue;
        }
        
        // For decimal searches, use precision-based matching
        std::string searchStr = std::to_string(searchValue);
        size_t decimalPos = searchStr.find('.');
        if (decimalPos != std::string::npos) {
            // Remove trailing zeros
            while (searchStr.back() == '0') searchStr.pop_back();
            if (searchStr.back() == '.') searchStr.pop_back();
            
            int decimalPlaces = searchStr.length() - decimalPos - 1;
            if (decimalPlaces > 0) {
                double tolerance = std::pow(10.0, -(double)decimalPlaces) * 0.5;
                return std::abs(searchValue - memoryValue) <= tolerance;
            }
        }
        
        // Default tolerance for edge cases
        return std::abs(searchValue - memoryValue) <= 0.001;
    }

    // Add valid result with memory validation
    template<typename T>
    void AddValidResult(DWORD_PTR foundAddr, T actualValue, DataType type) {
        // Validate that this address is in writable memory
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(processHandle, (LPCVOID)foundAddr, &mbi, sizeof(mbi))) {
            // Only include addresses in committed, writable memory
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY))) {
                
                MemoryResult result;
                result.address = foundAddr;
                result.type = type;
                result.size = sizeof(T);
                
                // Store the actual value found in memory
                result.value.resize(sizeof(T));
                memcpy(result.value.data(), &actualValue, sizeof(T));
                
                searchResults.push_back(result);
            }
        }
    }

    // Get size for data type
    size_t GetTypeSize(DataType type) {
        switch (type) {
            case TYPE_BYTE: return 1;
            case TYPE_2BYTE: return 2;
            case TYPE_4BYTE: return 4;
            case TYPE_FLOAT: return 4;
            case TYPE_DOUBLE: return 8;
            case TYPE_POINTER: return targetPointerSize;
            case TYPE_STRING: return 0; // Variable size
        }
        return 0;
    }

    // Search for value in process memory
    void SearchValue(const std::string& value, DataType type) {
        searchResults.clear();
        std::vector<BYTE> searchBytes = StringToBytes(value, type);
        size_t searchSize = (type == TYPE_STRING) ? searchBytes.size() : GetTypeSize(type);
        
        std::cout << "Searching for ";
        PrintValueWithType(searchBytes, type);
        if (type == TYPE_FLOAT || type == TYPE_DOUBLE) {
            std::cout << " (with fuzzy matching - will find similar decimal values)";
        }
        std::cout << std::endl;
        
        // First pass: count total regions
        MEMORY_BASIC_INFORMATION mbi;
        DWORD_PTR address = 0;
        int totalRegions = 0;
        
        while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_GUARD) == 0 && 
                (mbi.Protect & PAGE_NOACCESS) == 0) {
                totalRegions++;
            }
            address = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
        
        // Second pass: actual search with progress
        StartProgress("VALUE SCAN:", totalRegions);
        
        address = 0;
        int regionCount = 0;
        int searchableRegions = 0;
        
        while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi))) {
            regionCount++;
            
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_GUARD) == 0 && 
                (mbi.Protect & PAGE_NOACCESS) == 0) {
                
                searchableRegions++;
                SearchInRegion((DWORD_PTR)mbi.BaseAddress, mbi.RegionSize, searchBytes, type);
                UpdateProgress(searchableRegions);
            }
            
            address = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
        
        FinishProgress("Found " + std::to_string(searchResults.size()) + " results");
        
        std::cout << "Search complete. Found " << searchResults.size() << " results.\n";
        DisplayResults();
    }

    // Search in specific memory region with fuzzy matching for floats/doubles
    void SearchInRegion(DWORD_PTR baseAddr, SIZE_T size, const std::vector<BYTE>& searchBytes, DataType type) {
        const SIZE_T CHUNK_SIZE = 1024 * 1024; // 1MB chunks
        std::vector<BYTE> buffer(CHUNK_SIZE);
        
        // Extract search value for fuzzy matching
        float searchFloat = 0.0f;
        double searchDouble = 0.0;
        if (type == TYPE_FLOAT) {
            searchFloat = *(float*)searchBytes.data();
        } else if (type == TYPE_DOUBLE) {
            searchDouble = *(double*)searchBytes.data();
        }
        
        for (SIZE_T offset = 0; offset < size; offset += CHUNK_SIZE) {
            SIZE_T readSize = std::min(CHUNK_SIZE, size - offset);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, (LPCVOID)(baseAddr + offset), 
                                buffer.data(), readSize, &bytesRead)) {
                
                if (type == TYPE_FLOAT) {
                    // Fuzzy matching for floats
                    for (SIZE_T i = 0; i <= bytesRead - sizeof(float); i += sizeof(float)) {
                        float memoryValue = *(float*)(buffer.data() + i);
                        if (IsFloatFuzzyMatch(searchFloat, memoryValue)) {
                            DWORD_PTR foundAddr = baseAddr + offset + i;
                            AddValidResult(foundAddr, memoryValue, type);
                        }
                    }
                } else if (type == TYPE_DOUBLE) {
                    // Fuzzy matching for doubles
                    for (SIZE_T i = 0; i <= bytesRead - sizeof(double); i += sizeof(double)) {
                        double memoryValue = *(double*)(buffer.data() + i);
                        if (IsDoubleFuzzyMatch(searchDouble, memoryValue)) {
                            DWORD_PTR foundAddr = baseAddr + offset + i;
                            AddValidResult(foundAddr, memoryValue, type);
                        }
                    }
                } else {
                    // Exact matching for other types
                for (SIZE_T i = 0; i <= bytesRead - searchBytes.size(); i++) {
                    if (memcmp(buffer.data() + i, searchBytes.data(), searchBytes.size()) == 0) {
                            DWORD_PTR foundAddr = baseAddr + offset + i;
                            
                            // Validate that this address is in writable memory
                            MEMORY_BASIC_INFORMATION mbi;
                            if (VirtualQueryEx(processHandle, (LPCVOID)foundAddr, &mbi, sizeof(mbi))) {
                                // Only include addresses in committed, writable memory
                                if (mbi.State == MEM_COMMIT && 
                                    (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY))) {
                                    
                        MemoryResult result;
                                    result.address = foundAddr;
                        result.value = searchBytes;
                        result.type = type;
                        result.size = searchBytes.size();
                        searchResults.push_back(result);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Display search results
    void DisplayResults() {
        if (searchResults.empty()) {
            std::cout << "No results found.\n";
            return;
        }
        
        std::cout << "\nSearch Results:\n";
        std::cout << "Index | Address          | Value\n";
        std::cout << "------|------------------|------------------\n";
        
        for (size_t i = 0; i < std::min(searchResults.size(), (size_t)50); i++) {
            std::cout << std::setw(5) << i << " | 0x" 
                     << std::hex << std::setw(16) << std::setfill('0') 
                     << searchResults[i].address << std::dec << " | ";
            PrintValueWithType(searchResults[i].value, searchResults[i].type);
            std::cout << "\n";
        }
        
        if (searchResults.size() > 50) {
            std::cout << "... and " << (searchResults.size() - 50) << " more results.\n";
        }
    }

    // Print value with type information
    void PrintValueWithType(const std::vector<BYTE>& bytes, DataType type) {
        switch (type) {
            case TYPE_BYTE:
                std::cout << "BYTE: " << (int)bytes[0] << " (0x" << std::hex << (int)bytes[0] << std::dec << ")";
                break;
            case TYPE_2BYTE: {
                WORD val = *(WORD*)bytes.data();
                std::cout << "2-BYTE: " << val << " (0x" << std::hex << val << std::dec << ")";
                break;
            }
            case TYPE_4BYTE: {
                DWORD val = *(DWORD*)bytes.data();
                std::cout << "4-BYTE: " << val << " (0x" << std::hex << val << std::dec << ")";
                break;
            }
            case TYPE_FLOAT: {
                float val = *(float*)bytes.data();
                std::cout << "FLOAT: " << std::fixed << std::setprecision(6) << val;
                break;
            }
            case TYPE_DOUBLE: {
                double val = *(double*)bytes.data();
                std::cout << "DOUBLE: " << std::fixed << std::setprecision(10) << val;
                break;
            }
            case TYPE_STRING:
                std::cout << "STRING: \"" << std::string(bytes.begin(), bytes.end() - 1) << "\"";
                break;
            case TYPE_POINTER: {
                DWORD_PTR val = 0;
                if (targetPointerSize == 4) {
                    uint32_t v32;
                    memcpy(&v32, bytes.data(), 4);
                    val = static_cast<DWORD_PTR>(v32);
                } else {
                    uint64_t v64;
                    memcpy(&v64, bytes.data(), 8);
                    val = static_cast<DWORD_PTR>(v64);
                }
                std::cout << "POINTER: 0x" << std::hex << val << std::dec;
                break;
            }
        }
    }

    // Modify values using Python-style indexing
    void ModifyValues() {
        if (searchResults.empty()) {
            std::cout << "No search results to modify.\n";
            return;
        }
        
        std::cout << "Enter index/range (e.g., 5, 10:20, :50, 25:): ";
        std::string indexStr;
        std::cin.ignore();
        std::getline(std::cin, indexStr);
        
        std::vector<size_t> indices = ParsePythonIndices(indexStr, searchResults.size());
        
        if (indices.empty()) {
            std::cout << "Invalid index/range.\n";
            return;
        }
        
        std::cout << "Enter new value: ";
        std::string newValue;
        std::getline(std::cin, newValue);
        
        std::vector<BYTE> newBytes = StringToBytes(newValue, searchResults[indices[0]].type);
        
        int successCount = 0;
        for (size_t idx : indices) {
            DWORD_PTR address = searchResults[idx].address;
            SIZE_T size = newBytes.size();
            
            // First, validate the memory region
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
                if (idx < 5) {
                    std::cout << "Address 0x" << std::hex << address << std::dec 
                             << " - Invalid memory region (unmapped)\n";
                }
                continue;
            }
            
            // Check if memory is committed and accessible
            if (mbi.State != MEM_COMMIT) {
                if (idx < 5) {
                    std::cout << "Address 0x" << std::hex << address << std::dec 
                             << " - Memory not committed\n";
                }
                continue;
            }
            
            // Try to change memory protection to allow writing
            DWORD oldProtect;
            bool protectionChanged = VirtualProtectEx(processHandle, (LPVOID)address, 
                                                    size, PAGE_EXECUTE_READWRITE, &oldProtect);
            
            SIZE_T bytesWritten;
            if (WriteProcessMemory(processHandle, (LPVOID)address,
                                 newBytes.data(), size, &bytesWritten)) {
                successCount++;
            } else {
                DWORD error = GetLastError();
                if (idx < 5) { // Only show first 5 errors to avoid spam
                    std::cout << "Failed to write to address 0x" << std::hex 
                             << address << std::dec 
                             << " - Error: " << error;
                    switch (error) {
                        case ERROR_ACCESS_DENIED:
                            std::cout << " (Access Denied - Try running as Administrator)";
                            break;
                        case ERROR_INVALID_HANDLE:
                            std::cout << " (Invalid Process Handle)";
                            break;
                        case ERROR_PARTIAL_COPY:
                            std::cout << " (Memory Protection - Read-only region)";
                            break;
                        case 998: // ERROR_INVALID_ACCESS_TO_MEMORY_LOCATION
                            std::cout << " (Invalid Memory Location - Address may be unmapped or protected)";
                            break;
                        default:
                            std::cout << " (Unknown error)";
                    }
                    std::cout << std::endl;
                }
            }
            
            // Restore original protection
            if (protectionChanged) {
                VirtualProtectEx(processHandle, (LPVOID)address, size, oldProtect, &oldProtect);
            }
        }
        
        std::cout << "Successfully modified " << successCount << " out of " 
                 << indices.size() << " values.\n";
    }

    // Parse Python-style indices
    std::vector<size_t> ParsePythonIndices(const std::string& indexStr, size_t maxSize) {
        std::vector<size_t> indices;
        
        if (indexStr.find(':') != std::string::npos) {
            // Range notation
            size_t colonPos = indexStr.find(':');
            std::string startStr = indexStr.substr(0, colonPos);
            std::string endStr = indexStr.substr(colonPos + 1);
            
            size_t start = startStr.empty() ? 0 : std::stoul(startStr);
            size_t end = endStr.empty() ? maxSize : std::stoul(endStr);
            
            for (size_t i = start; i < end && i < maxSize; i++) {
                indices.push_back(i);
            }
        } else {
            // Single index
            size_t index = std::stoul(indexStr);
            if (index < maxSize) {
                indices.push_back(index);
            }
        }
        
        return indices;
    }

    // In-place progress display functions
    void StartProgress(const std::string& scanType, int total = 100) {
        currentScanType = scanType;
        currentProgress = 0;
        totalProgress = total;
        UpdateProgress(0);
    }
    
    void UpdateProgress(int progress) {
        currentProgress = progress;
        
        // Calculate percentage
        int percentage = (totalProgress > 0) ? (currentProgress * 100) / totalProgress : 0;
        percentage = std::min(100, percentage);
        
        // Create progress bar
        const int barWidth = 30;
        int filledWidth = (percentage * barWidth) / 100;
        
        std::string progressBar = "[";
        for (int i = 0; i < barWidth; i++) {
            if (i < filledWidth) {
                progressBar += "=";
            } else if (i == filledWidth && percentage < 100) {
                progressBar += ">";
            } else {
                progressBar += " ";
            }
        }
        progressBar += "]";
        
        // Print in-place (carriage return without newline)
        std::cout << "\r" << currentScanType << " " << progressBar 
                 << " " << percentage << "% (" << currentProgress;
        if (totalProgress > 0) {
            std::cout << "/" << totalProgress;
        }
        std::cout << ")";
        std::cout.flush();
    }
    
    void FinishProgress(const std::string& result = "") {
        UpdateProgress(totalProgress); // Show 100%
        std::cout << " - " << result << std::endl; // New line to finish
    }

    // Filter current search results
    void FilterResults() {
        if (searchResults.empty()) {
            std::cout << "No search results to filter. Perform a search first.\n";
            return;
        }

        std::cout << "Current results: " << searchResults.size() << " addresses\n";
        std::cout << "\n=== Filter Options ===\n";
        std::cout << "1. Filter by current value (re-read memory)\n";
        std::cout << "2. Filter by value range\n";
        std::cout << "3. Filter by address range\n";
        std::cout << "4. Filter by changed values\n";
        std::cout << "5. Filter by unchanged values\n";
        std::cout << "6. Filter by increased values\n";
        std::cout << "7. Filter by decreased values\n";
        std::cout << "Choice: ";

        int filterChoice;
        std::cin >> filterChoice;

        switch (filterChoice) {
            case 1:
                FilterByCurrentValue();
                break;
            case 2:
                FilterByValueRange();
                break;
            case 3:
                FilterByAddressRange();
                break;
            case 4:
                FilterByChanged();
                break;
            case 5:
                FilterByUnchanged();
                break;
            case 6:
                FilterByIncreased();
                break;
            case 7:
                FilterByDecreased();
                break;
            default:
                std::cout << "Invalid choice.\n";
                return;
        }

        std::cout << "Filter complete. Results: " << searchResults.size() << " addresses\n";
        DisplayResults();
    }

    // Filter by current value in memory
    void FilterByCurrentValue() {
        std::cout << "Enter value to filter by: ";
        std::string value;
        std::cin.ignore();
        std::getline(std::cin, value);

        if (searchResults.empty()) return;

        DataType type = searchResults[0].type;
        std::vector<BYTE> filterBytes = StringToBytes(value, type);
        
        std::vector<MemoryResult> filteredResults;
        
        StartProgress("FILTERING:", searchResults.size());
        
        for (size_t i = 0; i < searchResults.size(); i++) {
            auto& result = searchResults[i];
            
            // Update progress every 100 results
            if (i % 100 == 0) {
                UpdateProgress(i);
            }
            // Read current value from memory
            std::vector<BYTE> currentValue(result.size);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, (LPCVOID)result.address,
                                currentValue.data(), result.size, &bytesRead)) {
                
                bool matches = false;
                
                if (type == TYPE_FLOAT) {
                    float currentFloat = *(float*)currentValue.data();
                    float searchFloat = *(float*)filterBytes.data();
                    matches = IsFloatFuzzyMatch(searchFloat, currentFloat);
                } else if (type == TYPE_DOUBLE) {
                    double currentDouble = *(double*)currentValue.data();
                    double searchDouble = *(double*)filterBytes.data();
                    matches = IsDoubleFuzzyMatch(searchDouble, currentDouble);
                } else {
                    matches = (memcmp(currentValue.data(), filterBytes.data(), result.size) == 0);
                }
                
                if (matches) {
                    result.value = currentValue; // Update stored value
                    filteredResults.push_back(result);
                }
            }
        }
        
        searchResults = filteredResults;
    }

    // Filter by value range
    void FilterByValueRange() {
        if (searchResults.empty()) return;
        
        DataType type = searchResults[0].type;
        
        if (type == TYPE_STRING) {
            std::cout << "Range filtering not supported for strings.\n";
            return;
        }

        std::cout << "Enter minimum value: ";
        std::string minStr;
        std::cin >> minStr;
        
        std::cout << "Enter maximum value: ";
        std::string maxStr;
        std::cin >> maxStr;

        std::vector<MemoryResult> filteredResults;
        
        for (auto& result : searchResults) {
            // Read current value from memory
            std::vector<BYTE> currentValue(result.size);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, (LPCVOID)result.address,
                                currentValue.data(), result.size, &bytesRead)) {
                
                bool inRange = false;
                
                switch (type) {
                    case TYPE_BYTE: {
                        BYTE val = *(BYTE*)currentValue.data();
                        BYTE minVal = (BYTE)std::stoi(minStr);
                        BYTE maxVal = (BYTE)std::stoi(maxStr);
                        inRange = (val >= minVal && val <= maxVal);
                        break;
                    }
                    case TYPE_2BYTE: {
                        WORD val = *(WORD*)currentValue.data();
                        WORD minVal = (WORD)std::stoi(minStr);
                        WORD maxVal = (WORD)std::stoi(maxStr);
                        inRange = (val >= minVal && val <= maxVal);
                        break;
                    }
                    case TYPE_4BYTE: {
                        DWORD val = *(DWORD*)currentValue.data();
                        DWORD minVal = (DWORD)std::stoul(minStr);
                        DWORD maxVal = (DWORD)std::stoul(maxStr);
                        inRange = (val >= minVal && val <= maxVal);
                        break;
                    }
                    case TYPE_FLOAT: {
                        float val = *(float*)currentValue.data();
                        float minVal = std::stof(minStr);
                        float maxVal = std::stof(maxStr);
                        inRange = (val >= minVal && val <= maxVal);
                        break;
                    }
                    case TYPE_DOUBLE: {
                        double val = *(double*)currentValue.data();
                        double minVal = std::stod(minStr);
                        double maxVal = std::stod(maxStr);
                        inRange = (val >= minVal && val <= maxVal);
                        break;
                    }
                }
                
                if (inRange) {
                    result.value = currentValue; // Update stored value
                    filteredResults.push_back(result);
                }
            }
        }
        
        searchResults = filteredResults;
    }

    // Filter by address range
    void FilterByAddressRange() {
        std::cout << "Enter minimum address (hex, e.g., 0x400000): ";
        std::string minStr;
        std::cin >> minStr;
        
        std::cout << "Enter maximum address (hex, e.g., 0x500000): ";
        std::string maxStr;
        std::cin >> maxStr;

        DWORD_PTR minAddr = std::stoull(minStr, nullptr, 16);
        DWORD_PTR maxAddr = std::stoull(maxStr, nullptr, 16);

        std::vector<MemoryResult> filteredResults;
        
        for (const auto& result : searchResults) {
            if (result.address >= minAddr && result.address <= maxAddr) {
                filteredResults.push_back(result);
            }
        }
        
        searchResults = filteredResults;
    }

    // Filter by changed values
    void FilterByChanged() {
        std::vector<MemoryResult> filteredResults;
        
        for (auto& result : searchResults) {
            // Read current value from memory
            std::vector<BYTE> currentValue(result.size);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, (LPCVOID)result.address,
                                currentValue.data(), result.size, &bytesRead)) {
                
                // Compare with stored value
                if (memcmp(currentValue.data(), result.value.data(), result.size) != 0) {
                    result.value = currentValue; // Update stored value
                    filteredResults.push_back(result);
                }
            }
        }
        
        searchResults = filteredResults;
    }

    // Filter by unchanged values
    void FilterByUnchanged() {
        std::vector<MemoryResult> filteredResults;
        
        for (const auto& result : searchResults) {
            // Read current value from memory
            std::vector<BYTE> currentValue(result.size);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, (LPCVOID)result.address,
                                currentValue.data(), result.size, &bytesRead)) {
                
                // Compare with stored value
                if (memcmp(currentValue.data(), result.value.data(), result.size) == 0) {
                    filteredResults.push_back(result);
                }
            }
        }
        
        searchResults = filteredResults;
    }

    // Filter by increased values
    void FilterByIncreased() {
        if (searchResults.empty()) return;
        
        DataType type = searchResults[0].type;
        if (type == TYPE_STRING) {
            std::cout << "Increase/decrease filtering not supported for strings.\n";
            return;
        }

        std::vector<MemoryResult> filteredResults;
        
        for (auto& result : searchResults) {
            // Read current value from memory
            std::vector<BYTE> currentValue(result.size);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, (LPCVOID)result.address,
                                currentValue.data(), result.size, &bytesRead)) {
                
                bool increased = false;
                
                switch (type) {
                    case TYPE_BYTE:
                        increased = *(BYTE*)currentValue.data() > *(BYTE*)result.value.data();
                        break;
                    case TYPE_2BYTE:
                        increased = *(WORD*)currentValue.data() > *(WORD*)result.value.data();
                        break;
                    case TYPE_4BYTE:
                        increased = *(DWORD*)currentValue.data() > *(DWORD*)result.value.data();
                        break;
                    case TYPE_FLOAT:
                        increased = *(float*)currentValue.data() > *(float*)result.value.data();
                        break;
                    case TYPE_DOUBLE:
                        increased = *(double*)currentValue.data() > *(double*)result.value.data();
                        break;
                }
                
                if (increased) {
                    result.value = currentValue; // Update stored value
                    filteredResults.push_back(result);
                }
            }
        }
        
        searchResults = filteredResults;
    }

    // Filter by decreased values
    void FilterByDecreased() {
        if (searchResults.empty()) return;
        
        DataType type = searchResults[0].type;
        if (type == TYPE_STRING) {
            std::cout << "Increase/decrease filtering not supported for strings.\n";
            return;
        }

        std::vector<MemoryResult> filteredResults;
        
        for (auto& result : searchResults) {
            // Read current value from memory
            std::vector<BYTE> currentValue(result.size);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, (LPCVOID)result.address,
                                currentValue.data(), result.size, &bytesRead)) {
                
                bool decreased = false;
                
                switch (type) {
                    case TYPE_BYTE:
                        decreased = *(BYTE*)currentValue.data() < *(BYTE*)result.value.data();
                        break;
                    case TYPE_2BYTE:
                        decreased = *(WORD*)currentValue.data() < *(WORD*)result.value.data();
                        break;
                    case TYPE_4BYTE:
                        decreased = *(DWORD*)currentValue.data() < *(DWORD*)result.value.data();
                        break;
                    case TYPE_FLOAT:
                        decreased = *(float*)currentValue.data() < *(float*)result.value.data();
                        break;
                    case TYPE_DOUBLE:
                        decreased = *(double*)currentValue.data() < *(double*)result.value.data();
                        break;
                }
                
                if (decreased) {
                    result.value = currentValue; // Update stored value
                    filteredResults.push_back(result);
                }
            }
        }
        
        searchResults = filteredResults;
    }

    // Search for pointers to a specific address
    void SearchPointers() {
        std::cout << "Enter target address (hex, e.g., 0x12345678): ";
        std::string addrStr;
        std::cin >> addrStr;
        
        DWORD_PTR targetAddr = std::stoull(addrStr, nullptr, 16);
        
        std::cout << "Enter maximum offset from base (default 1000): ";
        std::string offsetStr;
        std::cin >> offsetStr;
        DWORD maxOffset = offsetStr.empty() ? 1000 : std::stoul(offsetStr);
        
        std::cout << "Enter maximum pointer depth (default 5): ";
        std::string depthStr;
        std::cin >> depthStr;
        int maxDepth = depthStr.empty() ? 5 : std::stoi(depthStr);
        
        std::cout << "Searching for pointers to 0x" << std::hex << targetAddr << std::dec 
                 << " with max offset " << maxOffset << " and max depth " << maxDepth << "...\n";
        
        pointerResults.clear();
        interruptSearch = false;
        
        // Perform pointer search (simplified without threading for compatibility)
        std::cout << "Press Ctrl+C to interrupt search if needed...\n";
            PerformPointerSearch(targetAddr, maxOffset, maxDepth);
        
        std::cout << "Pointer search complete. Found " << pointerResults.size() << " pointer paths.\n";
        DisplayPointerResults();
        
        if (!pointerResults.empty()) {
            SavePointerResults();
        }
    }

    // Perform the actual pointer search (Cheat Engine style)
    void PerformPointerSearch(DWORD_PTR targetAddr, DWORD maxOffset, int maxDepth) {
        std::cout << "=== Cheat Engine Style Pointer Search ===\n";
        std::cout << "Target: 0x" << std::hex << targetAddr << std::dec << "\n";
        std::cout << "Max Offset: " << maxOffset << ", Max Depth: " << maxDepth << "\n\n";
        
        // Step 1: Build comprehensive pointer map of entire process
        std::cout << "Step 1: Building pointer map of process memory...\n";
        std::map<DWORD_PTR, std::vector<DWORD_PTR>> pointerMap; // address -> list of addresses that point to it
        BuildPointerMap(pointerMap);
        
        std::cout << "Pointer map built with " << pointerMap.size() << " entries.\n\n";
        
        // Step 2: Find all addresses that contain our target
        std::cout << "Step 2: Finding direct references to target...\n";
        
        // First, validate that the target address is actually readable
        std::cout << "Validating target address 0x" << std::hex << targetAddr << std::dec << "...\n";
        if (!ValidateTargetAddress(targetAddr)) {
            std::cout << "ERROR: Target address is not readable or has changed!\n";
            std::cout << "Make sure the target process hasn't modified this memory.\n";
            return;
        }
        std::cout << "Target address is valid and readable.\n";
        
        // Check if target is in our scanned regions
        if (!IsAddressInScannedRegions(targetAddr)) {
            std::cout << "WARNING: Target address is not in scanned memory regions.\n";
            std::cout << "Target might be in stack, heap, or filtered regions.\n";
            std::cout << "Try searching for pointers to nearby addresses or use a different target.\n";
        }
        
        std::vector<DWORD_PTR> level0Pointers;
        auto it = pointerMap.find(targetAddr);
        if (it != pointerMap.end()) {
            level0Pointers = it->second;
        }
        
        std::cout << "Found " << level0Pointers.size() << " direct pointers to target.\n";
        
        // Show some debugging info about nearby addresses
        if (level0Pointers.empty()) {
            std::cout << "\nDEBUG: Checking nearby addresses for pointers...\n";
            CheckNearbyAddresses(targetAddr, pointerMap);
            
            std::cout << "\nNo direct pointers found. This could mean:\n";
            std::cout << "1. Target is in stack/heap memory (not scanned)\n";
            std::cout << "2. Target address has changed since you found it\n";
            std::cout << "3. Target is pointed to by calculated addresses (not static pointers)\n";
            std::cout << "4. Target is in a memory region we filtered out\n";
            
            // Automatically search nearby addresses (Cheat Engine behavior)
            std::cout << "\nAutomatically searching nearby addresses for structure-based pointers...\n";
            std::vector<std::pair<DWORD_PTR, int>> nearbyWithPointers;
            FindNearbyAddressesWithPointersParallel(targetAddr, pointerMap, nearbyWithPointers, maxOffset);
            
            if (!nearbyWithPointers.empty()) {
                SearchNearbyPointerPathsAutomatic(targetAddr, nearbyWithPointers, pointerMap, maxOffset, maxDepth);
        
        if (!pointerResults.empty()) {
                    std::cout << "\nPointer search completed.\n";
                    DisplayPointerResults();
            SavePointerResults();
                    return;
                }
            }
            
            std::cout << "\nNo pointer paths found to target or nearby addresses.\n";
            std::cout << "Target might be in dynamically allocated memory (heap/stack).\n";
            return;
        }
        
        std::cout << std::endl;
        
        // Step 3: Recursively build pointer chains
        std::cout << "Step 3: Building pointer chains...\n";
        StartProgress("POINTER CHAINS:", moduleMap.size());
        
        int moduleIndex = 0;
        for (const auto& module : moduleMap) {
            if (interruptSearch) break;
            
            moduleIndex++;
            UpdateProgress(moduleIndex);
            
            SearchPointerChains(module.second, module.first, targetAddr, 
                              pointerMap, maxOffset, maxDepth);
        }
        
        FinishProgress("Found " + std::to_string(pointerResults.size()) + " pointer paths");
    }

    // Fast parallelized pointer map building (Windows native threading for MinGW compatibility)
    void BuildPointerMap(std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap) {
        // Collect all scannable memory regions first
        std::vector<std::pair<DWORD_PTR, SIZE_T>> regions;
        CollectScannableRegions(regions);
        
        if (regions.empty()) {
            std::cout << "No scannable memory regions found!\n";
            return;
        }
        
        std::cout << "Found " << regions.size() << " scannable regions. Building pointer map...\n";
        StartProgress("POINTER MAP:", regions.size());
        std::cout << std::endl;
        
        // Reset counters
        regionsProcessed = 0;
        totalPointersFound = 0;
        
        // Determine optimal thread count
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        DWORD threadCount = std::min(sysInfo.dwNumberOfProcessors, (DWORD)8);
        if (threadCount == 0) threadCount = 4; // Fallback
        
        std::cout << "Using " << threadCount << " threads for scanning.\n";
        
        // Create thread data structures
        std::vector<ThreadData> threadDataArray(threadCount);
        std::vector<HANDLE> threadHandles(threadCount);
        
        // Divide regions among threads
        size_t regionsPerThread = regions.size() / threadCount;
        
        for (DWORD i = 0; i < threadCount; i++) {
            size_t startIdx = i * regionsPerThread;
            size_t endIdx = (i == threadCount - 1) ? regions.size() : (i + 1) * regionsPerThread;
            
            threadDataArray[i].memoryTool = this;
            threadDataArray[i].pointerMap = &pointerMap;
            threadDataArray[i].regions = &regions;
            threadDataArray[i].startIdx = startIdx;
            threadDataArray[i].endIdx = endIdx;
            
            threadHandles[i] = CreateThread(NULL, 0, ScanRegionsThreadProc, 
                                          &threadDataArray[i], 0, NULL);
        }
        
        // Monitor progress while threads work
        while (regionsProcessed < (LONG)regions.size() && !interruptSearch) {
            UpdateProgress(regionsProcessed);
            Sleep(100); // Windows Sleep instead of std::this_thread
        }
        
        // Wait for all threads to complete
        WaitForMultipleObjects(threadCount, threadHandles.data(), TRUE, INFINITE);
        
        // Clean up thread handles
        for (HANDLE handle : threadHandles) {
            CloseHandle(handle);
        }
        
        FinishProgress("Found " + std::to_string(totalPointersFound) + " pointers");
    }
    
    // Collect all memory regions suitable for pointer scanning
    void CollectScannableRegions(std::vector<std::pair<DWORD_PTR, SIZE_T>>& regions) {
        MEMORY_BASIC_INFORMATION mbi;
        DWORD_PTR address = 0;
        
        while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi))) {
            // Cheat Engine optimization: Only scan specific memory types
            bool isScannable = (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_GUARD) == 0 && 
                               (mbi.Protect & PAGE_NOACCESS) == 0);
            
            // Focus on likely pointer-containing regions
            bool isPointerRegion = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) ||
                                  (mbi.Type == MEM_PRIVATE) || // Heap allocations
                                  (mbi.Type == MEM_IMAGE);     // Module sections
            
            // Skip very small regions (likely not useful)
            bool isReasonableSize = mbi.RegionSize >= 4096; // At least 4KB
            
            if (isScannable && isPointerRegion && isReasonableSize) {
                regions.push_back({(DWORD_PTR)mbi.BaseAddress, mbi.RegionSize});
            }
            
            address = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
    }

    // Thread worker function for scanning regions (Windows native)
    void ScanRegionsThreaded(std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap,
                           const std::vector<std::pair<DWORD_PTR, SIZE_T>>& regions,
                           size_t startIdx, size_t endIdx) {
        
        // Each thread builds its own local map to avoid contention
        std::map<DWORD_PTR, std::vector<DWORD_PTR>> localMap;
        
        for (size_t i = startIdx; i < endIdx && !interruptSearch; i++) {
            DWORD_PTR baseAddr = regions[i].first;
            SIZE_T size = regions[i].second;
            
            int regionPointers = ScanRegionForPointersOptimized(baseAddr, size, localMap);
            
            // Thread-safe counter updates
            EnterCriticalSection(&counterCriticalSection);
            totalPointersFound += regionPointers;
            regionsProcessed++;
            LeaveCriticalSection(&counterCriticalSection);
        }
        
        // Merge local map into global map (thread-safe with critical section)
        if (!localMap.empty()) {
            EnterCriticalSection(&pointerMapCriticalSection);
            for (const auto& entry : localMap) {
                auto& globalList = pointerMap[entry.first];
                globalList.insert(globalList.end(), entry.second.begin(), entry.second.end());
            }
            LeaveCriticalSection(&pointerMapCriticalSection);
        }
    }

    // Optimized region scanning for pointers (Cheat Engine optimizations)
    int ScanRegionForPointersOptimized(DWORD_PTR baseAddr, SIZE_T size, 
                                      std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap) {
        const SIZE_T CHUNK_SIZE = 2 * 1024 * 1024; // 2MB chunks for better performance
        std::vector<BYTE> buffer(CHUNK_SIZE);
        int pointersFound = 0;
        
        for (SIZE_T offset = 0; offset < size && !interruptSearch; offset += CHUNK_SIZE) {
            SIZE_T readSize = std::min(CHUNK_SIZE, size - offset);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, (LPCVOID)(baseAddr + offset), 
                                buffer.data(), readSize, &bytesRead)) {
                
                // Cheat Engine optimization: Skip obviously non-pointer regions
                if (IsLikelyPointerRegion(buffer.data(), bytesRead)) {
                    pointersFound += ScanChunkForPointers(buffer.data(), bytesRead, 
                                                        baseAddr + offset, pointerMap);
                }
                
                // Prevent memory explosion per thread
                if (pointersFound > 500000) { // 500K pointers max per region per thread
                    break;
                }
            }
        }
        
        return pointersFound;
    }
    
    // Read pointer value from buffer based on target pointer size
    DWORD_PTR ReadPointerFromBuffer(const BYTE* data, SIZE_T offset) {
        if (targetPointerSize == 4) {
            uint32_t v32;
            memcpy(&v32, data + offset, 4);
            return static_cast<DWORD_PTR>(v32);
        }
        uint64_t v64;
        memcpy(&v64, data + offset, 8);
        return static_cast<DWORD_PTR>(v64);
    }

    // Read pointer value from process based on target pointer size
    bool ReadPointerValue(DWORD_PTR address, DWORD_PTR& outValue) {
        SIZE_T bytesRead = 0;
        if (targetPointerSize == 4) {
            uint32_t v32 = 0;
            if (!ReadProcessMemory(processHandle, (LPCVOID)address, &v32, 4, &bytesRead) || bytesRead != 4) {
                return false;
            }
            outValue = static_cast<DWORD_PTR>(v32);
            return true;
        }
        uint64_t v64 = 0;
        if (!ReadProcessMemory(processHandle, (LPCVOID)address, &v64, 8, &bytesRead) || bytesRead != 8) {
            return false;
        }
        outValue = static_cast<DWORD_PTR>(v64);
        return true;
    }

    // Check if a memory chunk is likely to contain pointers
    bool IsLikelyPointerRegion(const BYTE* data, SIZE_T size) {
        if (size < 64) return false;
        
        int validPointerCount = 0;
        int totalChecked = 0;
        
        // Sample every 64 bytes to check if region contains pointer-like values
        for (SIZE_T i = 0; i + targetPointerSize <= size && i < 256; i += 64) {
            DWORD_PTR value = ReadPointerFromBuffer(data, i);
            totalChecked++;
            
            // Quick pointer validation (without expensive memory checks)
            if (IsValidPointerFast(value)) {
                validPointerCount++;
            }
            
            if (totalChecked >= 16) break; // Sample enough
        }
        
        // If more than 10% of sampled values look like pointers, scan this region
        return (validPointerCount * 10 > totalChecked);
    }
    
    // Scan a memory chunk for pointers with optimizations
    int ScanChunkForPointers(const BYTE* data, SIZE_T size, DWORD_PTR baseAddr,
                           std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap) {
        int pointersFound = 0;
        
        // Cheat Engine optimization: Use SIMD-friendly loop
        for (SIZE_T i = 0; i + targetPointerSize <= size; i += targetPointerAlignment) {
            DWORD_PTR pointerValue = ReadPointerFromBuffer(data, i);
            
            // Fast pointer validation (most important optimization)
            if (IsValidPointerFast(pointerValue)) {
                DWORD_PTR pointerAddress = baseAddr + i;
                pointerMap[pointerValue].push_back(pointerAddress);
                pointersFound++;
            }
        }
        
        return pointersFound;
    }
    
    // Validate that target address is still readable and contains expected data
    bool ValidateTargetAddress(DWORD_PTR targetAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(processHandle, (LPCVOID)targetAddr, &mbi, sizeof(mbi)) == 0) {
            std::cout << "  Target address is not mapped in memory.\n";
            return false;
        }
        
        if (mbi.State != MEM_COMMIT) {
            std::cout << "  Target address is not committed memory.\n";
            return false;
        }
        
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) {
            std::cout << "  Target address is not accessible.\n";
            return false;
        }
        
        // Try to read a small amount of data from the target
        BYTE testData[4];
        SIZE_T bytesRead;
        if (!ReadProcessMemory(processHandle, (LPCVOID)targetAddr, testData, 4, &bytesRead)) {
            std::cout << "  Cannot read from target address.\n";
            return false;
        }
        
        std::cout << "  Target contains: 0x" << std::hex;
        for (int i = 0; i < 4; i++) {
            std::cout << std::setw(2) << std::setfill('0') << (int)testData[i];
        }
        std::cout << std::dec << std::endl;
        
        return true;
    }
    
    // Check if address is in our scanned regions
    bool IsAddressInScannedRegions(DWORD_PTR targetAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(processHandle, (LPCVOID)targetAddr, &mbi, sizeof(mbi)) == 0) {
            return false;
        }
        
        // Check if this region type would have been scanned
        bool isScannable = (mbi.State == MEM_COMMIT && 
                           (mbi.Protect & PAGE_GUARD) == 0 && 
                           (mbi.Protect & PAGE_NOACCESS) == 0);
        
        bool isPointerRegion = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) ||
                              (mbi.Type == MEM_PRIVATE) || // Heap allocations
                              (mbi.Type == MEM_IMAGE);     // Module sections
        
        bool isReasonableSize = mbi.RegionSize >= 4096;
        
        if (!isScannable) {
            std::cout << "  Target is in non-scannable memory (protected/guard pages).\n";
            return false;
        }
        
        if (!isPointerRegion) {
            std::cout << "  Target is in filtered memory type (Type: " << mbi.Type 
                     << ", Protect: 0x" << std::hex << mbi.Protect << std::dec << ").\n";
            return false;
        }
        
        if (!isReasonableSize) {
            std::cout << "  Target is in small memory region (" << mbi.RegionSize << " bytes).\n";
            return false;
        }
        
        return true;
    }
    
    // Check nearby addresses for debugging
    void CheckNearbyAddresses(DWORD_PTR targetAddr, const std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap) {
        std::cout << "Checking addresses near target:\n";
        
        int foundNearby = 0;
        for (int offset = -64; offset <= 64; offset += 4) {
            if (offset == 0) continue; // Skip the target itself
            
            DWORD_PTR checkAddr = targetAddr + offset;
            auto it = pointerMap.find(checkAddr);
            if (it != pointerMap.end() && !it->second.empty()) {
                std::cout << "  0x" << std::hex << checkAddr << std::dec 
                         << " (target" << std::showpos << offset << std::noshowpos 
                         << ") has " << it->second.size() << " pointers\n";
                foundNearby++;
                if (foundNearby >= 5) break; // Limit output
            }
        }
        
        if (foundNearby == 0) {
            std::cout << "  No pointers found to nearby addresses either.\n";
        }
    }
    
    // Fast parallelized structure scan using max offset range
    void FindNearbyAddressesWithPointersParallel(DWORD_PTR targetAddr, 
                                                const std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap,
                                                std::vector<std::pair<DWORD_PTR, int>>& nearbyWithPointers,
                                                DWORD maxOffset) {
        
        // Calculate scan range based on max offset (structure size assumption)
        int scanRange = std::min((int)maxOffset, 8192); // Cap at 8KB for performance
        int totalOffsets = (scanRange * 2) / 4; // Number of 4-byte aligned offsets to check
        
        std::cout << "Scanning +/-" << scanRange << " bytes around target for structure pointers...\n";
        StartProgress("STRUCTURE SCAN:", totalOffsets);
        
        // Determine optimal thread count for structure scanning
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        DWORD threadCount = std::min(sysInfo.dwNumberOfProcessors, (DWORD)4); // Max 4 threads for this
        if (threadCount == 0) threadCount = 2;
        
        // Thread-safe results collection
        std::vector<std::vector<std::pair<DWORD_PTR, int>>> threadResults(threadCount);
        std::vector<HANDLE> threadHandles(threadCount);
        std::vector<StructureScanData> threadDataArray(threadCount);
        
        // Divide offset range among threads
        int offsetsPerThread = totalOffsets / threadCount;
        
        for (DWORD i = 0; i < threadCount; i++) {
            int startOffset = -scanRange + (i * offsetsPerThread * 4);
            int endOffset = (i == threadCount - 1) ? scanRange : (-scanRange + ((i + 1) * offsetsPerThread * 4));
            
            threadDataArray[i].targetAddr = targetAddr;
            threadDataArray[i].pointerMap = &pointerMap;
            threadDataArray[i].results = &threadResults[i];
            threadDataArray[i].startOffset = startOffset;
            threadDataArray[i].endOffset = endOffset;
            threadDataArray[i].memoryTool = this;
            
            threadHandles[i] = CreateThread(NULL, 0, StructureScanThreadProc, 
                                          &threadDataArray[i], 0, NULL);
        }
        
        // Monitor progress
        int totalProcessed = 0;
        while (totalProcessed < totalOffsets && !interruptSearch) {
            // Calculate total progress from all threads
            totalProcessed = 0;
            for (DWORD i = 0; i < threadCount; i++) {
                totalProcessed += threadDataArray[i].processed;
            }
            UpdateProgress(totalProcessed);
            Sleep(50);
        }
        
        // Wait for all threads to complete
        WaitForMultipleObjects(threadCount, threadHandles.data(), TRUE, INFINITE);
        
        // Clean up thread handles
        for (HANDLE handle : threadHandles) {
            CloseHandle(handle);
        }
        
        // Merge results from all threads
        for (const auto& threadResult : threadResults) {
            nearbyWithPointers.insert(nearbyWithPointers.end(), 
                                    threadResult.begin(), threadResult.end());
        }
        
        // Sort by closeness to target first, then by number of pointers
        std::sort(nearbyWithPointers.begin(), nearbyWithPointers.end(), 
                 [&pointerMap](const std::pair<DWORD_PTR, int>& a, const std::pair<DWORD_PTR, int>& b) {
                    int distA = std::abs(a.second);
                    int distB = std::abs(b.second);
                    if (distA != distB) {
                        return distA < distB; // closer offsets first
                    }
                    return pointerMap.at(a.first).size() > pointerMap.at(b.first).size();
                 });
        
        FinishProgress("Found " + std::to_string(nearbyWithPointers.size()) + " structure candidates");
    }
    
    // Parallelized search for pointer paths to nearby addresses
    void SearchNearbyPointerPathsAutomatic(DWORD_PTR originalTarget,
                                          const std::vector<std::pair<DWORD_PTR, int>>& nearbyWithPointers,
                                          const std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap,
                                          DWORD maxOffset, int maxDepth) {
        
        pointerResults.clear(); // Start fresh
        
        // Limit to top candidates to prevent excessive processing
        size_t candidatesToProcess = std::min((size_t)20, nearbyWithPointers.size());
        std::cout << "Processing top " << candidatesToProcess << " structure candidates...\n";
        std::cout << "Press 'p' at any time to see all paths found so far, or 'q' to stop search.\n";
        
        // Calculate total work units (candidates × modules)
        int totalWorkUnits = candidatesToProcess * moduleMap.size();
        StartProgress("POINTER CHAINS:", totalWorkUnits);
        
        // Process candidates in batches for better progress reporting
        volatile LONG workUnitsCompleted = 0;
        
        for (size_t candidateIdx = 0; candidateIdx < candidatesToProcess; candidateIdx++) {
            if (interruptSearch) break;
            
            const auto& nearby = nearbyWithPointers[candidateIdx];
            DWORD_PTR nearbyAddr = nearby.first;
            int structOffset = nearby.second;
            
            // Check if this candidate has direct pointers
            auto it = pointerMap.find(nearbyAddr);
            if (it == pointerMap.end() || it->second.empty()) {
                // Skip this candidate, update progress for all its modules
                InterlockedExchangeAdd(&workUnitsCompleted, moduleMap.size());
                continue;
            }
            
            std::cout << "\nCandidate " << (candidateIdx + 1) << "/" << candidatesToProcess 
                     << ": 0x" << std::hex << nearbyAddr << std::dec 
                     << " (offset " << std::showpos << structOffset << std::noshowpos 
                     << ") - " << it->second.size() << " direct pointers\n";
            
            // Search each module for this candidate
            int moduleIndex = 0;
            for (const auto& module : moduleMap) {
                if (interruptSearch) break;
                
                // Check for user input
                if (_kbhit()) {
                    char key = _getch();
                    if (key == 'p' || key == 'P') {
                        std::cout << "\n=== PATHS FOUND SO FAR ===\n";
                        DisplayCurrentPaths();
                        std::cout << "=== CONTINUING SEARCH ===\n";
                    } else if (key == 'q' || key == 'Q') {
                        std::cout << "\nSearch interrupted by user.\n";
                        interruptSearch = true;
                        break;
                    }
                }
                
                moduleIndex++;
                std::cout << "  Checking " << module.first << "... ";
                std::cout.flush();
                
                int pathsBefore = pointerResults.size();
                SearchPointerChainsWithOffset(module.second, module.first, nearbyAddr, 
                                            originalTarget, structOffset, pointerMap, maxOffset, maxDepth);
                int pathsFound = pointerResults.size() - pathsBefore;
                
                if (pathsFound > 0) {
                    std::cout << "Found " << pathsFound << " paths!" << std::endl;
                    
                    // Show the newly found paths immediately
                    std::cout << "  New paths found:\n";
                    for (int i = pathsBefore; i < (int)pointerResults.size(); i++) {
                        const auto& path = pointerResults[i];
                        std::cout << "    " << (i + 1) << ": [[" << path.baseName << "+0x" << std::hex << path.offsets[0] << "]";
                        for (size_t j = 1; j < path.offsets.size(); j++) {
                            std::cout << "+0x" << path.offsets[j];
                        }
                        std::cout << "]";
                        
                        // Add structure offset separately
                        if (path.finalOffset != 0) {
                            if (path.finalOffset > 0) {
                                std::cout << "+0x" << path.finalOffset;
                            } else {
                                std::cout << "-0x" << (-path.finalOffset);
                            }
                        }
                        
                        std::cout << " = 0x" << path.finalAddress << std::dec << std::endl;
                    }
                    std::cout << std::endl;
                } else {
                    std::cout << "No paths" << std::endl;
                }
                
                InterlockedIncrement(&workUnitsCompleted);
                UpdateProgress(workUnitsCompleted);
                
                // Stop if we found enough paths
                if (pointerResults.size() >= 50) {
                    std::cout << "Found 50+ paths, stopping search for efficiency.\n";
                    InterlockedExchangeAdd(&workUnitsCompleted, totalWorkUnits - workUnitsCompleted);
                    break;
                }
            }
            
            // Show summary for this candidate
            int candidatePaths = 0;
            for (const auto& path : pointerResults) {
                if (path.originalTarget == originalTarget) candidatePaths++;
            }
            std::cout << "Candidate " << (candidateIdx + 1) << " total: " << candidatePaths << " paths found so far.\n\n";
            
            if (pointerResults.size() >= 50) break;
        }
        
        FinishProgress("Found " + std::to_string(pointerResults.size()) + " complete paths");
        
        // Sort results to show game modules first, system modules last (like Cheat Engine)
        if (!pointerResults.empty()) {
            SortPointerResultsByRelevance();
        }
    }
    
    // Sort pointer results by relevance (game modules first, system modules last)
    void SortPointerResultsByRelevance() {
        std::sort(pointerResults.begin(), pointerResults.end(), 
                 [this](const PointerPath& a, const PointerPath& b) {
                     // Calculate relevance score for each path
                     int scoreA = GetModuleRelevanceScore(a.baseName);
                     int scoreB = GetModuleRelevanceScore(b.baseName);
                     
                     if (scoreA != scoreB) {
                         return scoreA > scoreB; // Higher score first
                     }
                     
                     // If same relevance, prefer shorter chains
                     if (a.depth != b.depth) {
                         return a.depth < b.depth;
                     }
                     
                     // If same depth, prefer smaller structure offsets
                     return abs(a.finalOffset) < abs(b.finalOffset);
                 });
    }
    
    // Get relevance score for a module (higher = more relevant for games)
    int GetModuleRelevanceScore(const std::string& moduleName) {
        std::string nameLower = moduleName;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
        
        // Game executables (highest priority)
        if (nameLower.find(".exe") != std::string::npos) {
            return 100;
        }
        
        // Game-related DLLs (high priority)
        std::vector<std::string> gameKeywords = {
            "game", "engine", "unity", "unreal", "graphics", "render", 
            "dx", "opengl", "vulkan", "steam", "client"
        };
        
        for (const auto& keyword : gameKeywords) {
            if (nameLower.find(keyword) != std::string::npos) {
                return 80;
            }
        }
        
        // System DLLs (lower priority, but still shown)
        std::vector<std::string> systemDlls = {
            "kernel32", "ntdll", "user32", "advapi32", "gdi32", 
            "shell32", "ole32", "winmm", "msvcrt"
        };
        
        for (const auto& sysDll : systemDlls) {
            if (nameLower.find(sysDll) != std::string::npos) {
                return 10; // Low priority but still included
            }
        }
        
        // Unknown DLLs (medium priority)
        return 50;
    }
    
    // Display current paths found during search
    void DisplayCurrentPaths() {
        if (pointerResults.empty()) {
            std::cout << "No paths found yet.\n";
            return;
        }
        
        std::cout << "Current Paths Found (" << pointerResults.size() << " total):\n";
        std::cout << "Index | Complete Pointer Path = Final Address\n";
        std::cout << "------|------------------------------------------\n";
        
        for (size_t i = 0; i < pointerResults.size(); i++) {
            const auto& path = pointerResults[i];
            std::cout << std::setw(5) << i << " | [[" << path.baseName << "+0x" << std::hex << path.offsets[0] << "]";
            for (size_t j = 1; j < path.offsets.size(); j++) {
                std::cout << "+0x" << path.offsets[j];
            }
            std::cout << "]";
            
            // Add structure offset separately
            if (path.finalOffset != 0) {
                if (path.finalOffset > 0) {
                    std::cout << "+0x" << path.finalOffset;
                } else {
                    std::cout << "-0x" << (-path.finalOffset);
                }
            }
            
            std::cout << " = 0x" << path.finalAddress << std::dec << "\n";
        }
        std::cout << std::endl;
    }
    
    // Search pointer chains and automatically add the structure offset
    void SearchPointerChainsWithOffset(DWORD_PTR baseAddr, const std::string& baseName, 
                                     DWORD_PTR nearbyTarget, DWORD_PTR originalTarget, int structOffset,
                                     const std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap,
                                     DWORD maxOffset, int maxDepth) {
        
        std::vector<DWORD> currentPath;
        DWORD startTick = GetTickCount();
        DWORD lastLogTick = startTick;
        int offsetsScanned = 0;
        int pathsBefore = (int)pointerResults.size();
        int logEveryOffsets = 250;
        DWORD logEveryMs = 1000;

        SearchPointerChainRecursiveWithOffset(baseAddr, baseName, nearbyTarget, originalTarget, 
                                            structOffset, pointerMap, maxOffset, maxDepth,
                                            currentPath, 0, offsetsScanned, pathsBefore, startTick, lastLogTick,
                                            logEveryOffsets, logEveryMs);

        DWORD elapsed = GetTickCount() - startTick;
        int pathsFound = (int)pointerResults.size() - pathsBefore;
        std::cout << "  " << baseName << ": scanned " << offsetsScanned
                  << " offsets, found " << pathsFound
                  << " paths in " << elapsed << "ms\n";
    }
    
    // Optimized recursive pointer chain search with early termination
    int SearchPointerChainRecursiveWithOffset(DWORD_PTR currentAddr, const std::string& baseName,
                                            DWORD_PTR nearbyTarget, DWORD_PTR originalTarget, int structOffset,
                                            const std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap,
                                            DWORD maxOffset, int maxDepth,
                                            std::vector<DWORD>& currentPath, int currentDepth,
                                            int& offsetsScanned, int pathsBefore,
                                            DWORD startTick, DWORD& lastLogTick,
                                            int logEveryOffsets, DWORD logEveryMs) {
        
        if (interruptSearch || currentDepth >= maxDepth) return 0;
        
        int pathsFound = 0;
        
        // Use pointer alignment to avoid missing valid offsets
        DWORD step = (currentDepth == 0) ? (DWORD)targetPointerAlignment : 4;
        
        for (DWORD offset = 0; offset <= maxOffset && !interruptSearch; offset += step) {
            DWORD_PTR checkAddr = currentAddr + offset;
            DWORD_PTR value;

            if (!ReadPointerValue(checkAddr, value)) {
                continue;
            }

            if (currentDepth == 0) {
                offsetsScanned++;
                DWORD now = GetTickCount();
                if ((offsetsScanned % logEveryOffsets) == 0 || (now - lastLogTick) >= logEveryMs) {
                    int pathsFoundSoFar = (int)pointerResults.size() - pathsBefore;
                    std::cout << "    " << baseName << ": scanned " << offsetsScanned
                              << "/" << (maxOffset / step)
                              << " offsets, paths " << pathsFoundSoFar
                              << ", elapsed " << (now - startTick) << "ms\n";
                    lastLogTick = now;
                }
            }
            
            // Quick validation: Is this a reasonable pointer value?
            if (value < 0x10000 || static_cast<uint64_t>(value) > targetMaxUserAddress || (value & (targetPointerAlignment - 1)) != 0) {
                continue;
            }
            
            // Check if this value points directly to our nearby target
            if (value == nearbyTarget) {
                // Found a complete path! Create the final pointer path
                        PointerPath path;
                        path.baseName = baseName;
                path.baseAddress = currentAddr;
                path.offsets = currentPath;
                        path.offsets.push_back(offset);
                
                // DON'T add structure offset as an offset - it's handled in final address calculation
                // The path points to nearbyTarget, finalAddress is calculated as nearbyTarget + structOffset
                
                path.finalAddress = originalTarget;
                path.originalTarget = originalTarget;
                path.finalOffset = structOffset;
                path.depth = currentDepth + 1; // Correct depth - don't add extra for structure offset
                
                // Validate this is a reasonable pointer path AND actually works
                if (IsReasonablePointerPath(path) && ValidatePointerPath(path)) {
                        pointerResults.push_back(path);
                    pathsFound++;
                }
                
                if (pathsFound >= 5) return pathsFound; // Reduced limit for faster search
                continue;
            }
            
            // Only recurse if we haven't found enough paths and this looks promising
            if (pathsFound < 3 && currentDepth < maxDepth - 1) {
                auto it = pointerMap.find(value);
                if (it != pointerMap.end() && it->second.size() > 0) {
                    // Recursively search from this new address
                    std::vector<DWORD> newPath = currentPath;
                    newPath.push_back(offset);
                    
                    int subPaths = SearchPointerChainRecursiveWithOffset(value, baseName, nearbyTarget, originalTarget,
                                                                       structOffset, pointerMap, maxOffset, maxDepth,
                                                                       newPath, currentDepth + 1,
                                                                       offsetsScanned, pathsBefore, startTick, lastLogTick,
                                                                       logEveryOffsets, logEveryMs);
                    pathsFound += subPaths;
                    
                    if (pathsFound >= 5) return pathsFound; // Early termination
                }
            }
        }
        
        return pathsFound;
    }
    
    // Fast pointer validation without expensive system calls
    bool IsValidPointerFast(DWORD_PTR value) {
        // Basic range checks (very fast)
        if (value < 0x10000) return false;           // Too low
        if (static_cast<uint64_t>(value) > targetMaxUserAddress) return false;    // Too high for user space
        if ((value & (targetPointerAlignment - 1)) != 0) return false; // Not aligned
        
        // Cheat Engine optimization: Skip expensive VirtualQueryEx for speed
        // We'll validate these during pointer chain building instead
        return true;
    }
    
    // Validate if a pointer path is reasonable (minimal filtering like Cheat Engine)
    bool IsReasonablePointerPath(const PointerPath& path) {
        // Only filter out obviously broken paths, not by module name
        
        // Filter out excessively deep pointer chains (>8 levels is very unusual)
        if (path.depth > 8) {
            return false;
        }
        
        // Filter out paths with extremely large structure offsets (>64KB is unrealistic)
        if (abs(path.finalOffset) > 65536) {
            return false;
        }
        
        // Allow all modules - let user decide what's useful
        // Cheat Engine shows all results and lets users filter manually
        
        return true;
    }
    
    // Actually validate that a pointer path works by following it
    bool ValidatePointerPath(const PointerPath& path) {
        // Get the module base address
        auto moduleIt = moduleMap.find(path.baseName);
        if (moduleIt == moduleMap.end()) {
            return false; // Module not found
        }
        
        DWORD_PTR currentAddr = moduleIt->second; // Start with module base
        
        // Follow the pointer chain step by step
        for (size_t i = 0; i < path.offsets.size(); i++) {
            currentAddr += path.offsets[i];
            
            // If this is not the last step, read the pointer value
            if (i < path.offsets.size() - 1) {
                DWORD_PTR nextAddr;

                if (!ReadPointerValue(currentAddr, nextAddr)) {
                    return false; // Can't read this step
                }
                
                currentAddr = nextAddr;
                
                // Validate the intermediate address is reasonable
                if (currentAddr < 0x10000 || currentAddr > 0x7FFFFFFFFFFF) {
                    return false; // Invalid intermediate address
                }
            }
        }
        
        // Apply the final structure offset
        currentAddr += path.finalOffset;
        
        // Check if we actually reached the target address
        if (currentAddr != path.finalAddress) {
            return false; // Path doesn't lead to claimed target
        }
        
        // Final validation: Can we read from the final address?
        BYTE testData[4];
        SIZE_T bytesRead;
        if (!ReadProcessMemory(processHandle, (LPCVOID)currentAddr, testData, 4, &bytesRead)) {
            return false; // Can't read final address
        }
        
        return true; // Path is valid!
    }
    
    // Check if a value looks like a valid pointer
    bool IsValidPointer(DWORD_PTR value) {
        // Basic pointer validation
        if (value < 0x10000) return false; // Too low
        if (static_cast<uint64_t>(value) > targetMaxUserAddress) return false; // Too high for user space
        if ((value & (targetPointerAlignment - 1)) != 0) return false; // Not aligned
        
        // Check if the address is actually readable
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(processHandle, (LPCVOID)value, &mbi, sizeof(mbi)) == 0) {
            return false;
        }
        
        return (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_GUARD) == 0 && 
                (mbi.Protect & PAGE_NOACCESS) == 0);
    }

    // Search for pointer chains recursively (Cheat Engine style)
    void SearchPointerChains(DWORD_PTR baseAddr, const std::string& baseName, 
                            DWORD_PTR targetAddr, 
                            const std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap,
                            DWORD maxOffset, int maxDepth) {
        
        std::vector<DWORD> currentPath;
        int pathsFound = 0;
        int initialPathCount = pointerResults.size();
        
        // Start recursive search from this module base
        pathsFound = SearchPointerChainRecursive(baseAddr, baseName, targetAddr, 
                                                pointerMap, maxOffset, maxDepth, 
                                                currentPath, 0);
        
        // Update the current scan type to show module progress
        currentScanType = "SCANNING " + baseName + ":";
    }
    
    // Recursive pointer chain search
    int SearchPointerChainRecursive(DWORD_PTR currentAddr, const std::string& baseName,
                                   DWORD_PTR targetAddr,
                                   const std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap,
                                   DWORD maxOffset, int maxDepth,
                                   std::vector<DWORD>& currentPath, int currentDepth) {
        
        if (interruptSearch || currentDepth >= maxDepth) return 0;
        
        int pathsFound = 0;
        
        // Try different offsets from current address
        for (DWORD offset = 0; offset <= maxOffset && !interruptSearch; offset += 4) {
            DWORD_PTR checkAddr = currentAddr + offset;
            DWORD_PTR value;

            if (!ReadPointerValue(checkAddr, value)) {
                continue;
            }
            
            // Check if this value points directly to our target
            if (value == targetAddr) {
                // Found a complete path!
                PointerPath path;
                path.baseName = baseName;
                path.baseAddress = currentAddr;
                path.offsets = currentPath;
                path.offsets.push_back(offset);
                path.finalAddress = targetAddr;
                path.depth = currentDepth + 1;
                            pointerResults.push_back(path);
                pathsFound++;
                
                // Display the path
                std::cout << "Found path: " << baseName;
                for (size_t i = 0; i < path.offsets.size(); i++) {
                    std::cout << "+0x" << std::hex << path.offsets[i] << std::dec;
                }
                std::cout << " -> 0x" << std::hex << targetAddr << std::dec << "\n";
                
                if (pathsFound >= 100) return pathsFound; // Limit results
                continue;
            }
            
            // Check if this value is in our pointer map (points to something useful)
            auto it = pointerMap.find(value);
            if (it != pointerMap.end() && currentDepth < maxDepth - 1) {
                // This address points to something that has pointers to it
                // Recursively search from this new address
                std::vector<DWORD> newPath = currentPath;
                newPath.push_back(offset);
                
                int subPaths = SearchPointerChainRecursive(value, baseName, targetAddr,
                                                         pointerMap, maxOffset, maxDepth,
                                                         newPath, currentDepth + 1);
                pathsFound += subPaths;
                
                if (pathsFound >= 100) return pathsFound; // Limit results
            }
            
            // Show progress occasionally
            if (currentDepth == 0 && offset % 2000 == 0 && offset > 0) {
                std::cout << "  Checked " << baseName << " offset 0x" 
                         << std::hex << offset << std::dec << " (found " << pathsFound << " paths so far)\n";
            }
        }
        
        return pathsFound;
    }

    // Display pointer search results in Cheat Engine format
    void DisplayPointerResults() {
        if (pointerResults.empty()) {
            std::cout << "No pointer paths found.\n";
            return;
        }
        
        std::cout << "\nPointer Paths Found (Cheat Engine Format):\n";
        std::cout << "Index | Complete Pointer Path = Final Address\n";
        std::cout << "------|------------------------------------------\n";
        
        for (size_t i = 0; i < std::min(pointerResults.size(), (size_t)50); i++) {
            const auto& path = pointerResults[i];
            std::cout << std::setw(5) << i << " | ";
            
            // Format complete pointer path exactly like Cheat Engine
            std::cout << "[[" << path.baseName << "+0x" << std::hex << path.offsets[0] << "]";
            for (size_t j = 1; j < path.offsets.size(); j++) {
                std::cout << "+0x" << path.offsets[j];
            }
            std::cout << "]";
            
            // Add structure offset separately if needed
            if (path.finalOffset != 0) {
                if (path.finalOffset > 0) {
                    std::cout << "+0x" << std::hex << path.finalOffset << std::dec;
                } else {
                    std::cout << "-0x" << std::hex << (-path.finalOffset) << std::dec;
                }
            }
            
            std::cout << " = 0x" << std::hex << path.finalAddress << std::dec << "\n";
        }
        
        if (pointerResults.size() > 50) {
            std::cout << "... and " << (pointerResults.size() - 50) << " more paths.\n";
        }
        
        // Show usage example
        if (!pointerResults.empty()) {
            std::cout << "\nUsage Example:\n";
            const auto& example = pointerResults[0];
            std::cout << "Pointer Path: [[" << example.baseName << "+0x" << std::hex << example.offsets[0] << "]";
            for (size_t i = 1; i < example.offsets.size(); i++) {
                if (i == example.offsets.size() - 1 && example.finalOffset != 0) {
                    if (example.offsets[i] >= 0) {
                std::cout << "+0x" << example.offsets[i];
                    } else {
                        std::cout << "-0x" << (-example.offsets[i]);
                    }
                } else {
                    std::cout << "+0x" << example.offsets[i];
                }
            }
            std::cout << "]\n";
            std::cout << "This resolves to: 0x" << example.finalAddress << std::dec << " (your target address)\n";
            std::cout << "\nIn your trainer/cheat:\n";
            std::cout << "DWORD_PTR target = ReadPointer([[" << example.baseName << "+0x" << std::hex << example.offsets[0] << "]";
            for (size_t i = 1; i < example.offsets.size(); i++) {
                std::cout << "+0x" << example.offsets[i];
            }
            std::cout << "]);" << std::dec << "\n";
        }
    }

    // Save pointer results to file
    void SavePointerResults() {
        std::string filename = "pointer_scan_" + processName + "_" + 
                              std::to_string(GetTickCount()) + ".txt";
        
        std::ofstream file(filename);
        if (!file.is_open()) {
            std::cout << "Failed to create save file.\n";
            return;
        }
        
        file << "Pointer Scan Results\n";
        file << "Process: " << processName << "\n";
        file << "Total paths found: " << pointerResults.size() << "\n\n";
        
        for (size_t i = 0; i < pointerResults.size(); i++) {
            const auto& path = pointerResults[i];
            file << "Path " << i << ": ";
            file << "[[" << path.baseName << "+0x" << std::hex << path.offsets[0] << "]";
            for (size_t j = 1; j < path.offsets.size(); j++) {
                file << "+0x" << path.offsets[j];
            }
            file << "] -> 0x" << path.finalAddress << std::dec << "\n";
            
            // Add human-readable explanation
            file << "  Explanation: Read pointer at " << path.baseName << " + 0x" 
                 << std::hex << path.offsets[0] << std::dec;
            for (size_t j = 1; j < path.offsets.size(); j++) {
                file << ", then add 0x" << std::hex << path.offsets[j] << std::dec;
            }
            file << " to reach final address\n\n";
        }
        
        file.close();
        std::cout << "Pointer scan results saved to: " << filename << "\n";
    }

    // Main menu loop
    void Run() {
        std::cout << "=== Memory Tool v1.0 ===\n";
        std::cout << "A Cheat Engine-like memory manipulation tool\n";
        std::cout << "WARNING: For memory modification to work, run as Administrator!\n\n";
        
        std::string processSubstring;
        std::cout << "Enter process name substring (e.g., 'forza' for ForzaHorizon5.exe): ";
        std::cin >> processSubstring;
        
        if (!AttachToProcess(processSubstring)) {
            return;
        }
        
        while (true) {
            std::cout << "\n=== Main Menu ===\n";
            std::cout << "1. Search for value in memory\n";
            std::cout << "2. Modify found values\n";
            std::cout << "3. Filter current results\n";
            std::cout << "4. Search for pointers to address\n";
            std::cout << "5. Exit\n";
            std::cout << "Choice: ";
            
            int choice;
            std::cin >> choice;
            
            switch (choice) {
                case 1:
                    HandleValueSearch();
                    break;
                case 2:
                    ModifyValues();
                    break;
                case 3:
                    FilterResults();
                    break;
                case 4:
                    SearchPointers();
                    break;
                case 5:
                    std::cout << "Goodbye!\n";
                    return;
                default:
                    std::cout << "Invalid choice.\n";
            }
        }
    }

    // Handle value search menu
    void HandleValueSearch() {
        std::cout << "\nSelect data type:\n";
        std::cout << "1. Byte (1 byte)\n";
        std::cout << "2. 2-Byte (short/word)\n";
        std::cout << "3. 4-Byte (int/dword)\n";
        std::cout << "4. Float (4 bytes)\n";
        std::cout << "5. Double (8 bytes)\n";
        std::cout << "6. String (null-terminated)\n";
        std::cout << "7. Pointer (address)\n";
        std::cout << "Choice: ";
        
        int typeChoice;
        std::cin >> typeChoice;
        
        if (typeChoice < 1 || typeChoice > 7) {
            std::cout << "Invalid type selection.\n";
            return;
        }
        
        DataType type = (DataType)typeChoice;
        
        std::cout << "Enter value to search for: ";
        std::string value;
        std::cin.ignore();
        std::getline(std::cin, value);
        
        SearchValue(value, type);
    }
};

// Windows thread procedure for pointer scanning
DWORD WINAPI ScanRegionsThreadProc(LPVOID lpParam) {
    ThreadData* data = static_cast<ThreadData*>(lpParam);
    
    try {
        data->memoryTool->ScanRegionsThreaded(*data->pointerMap, *data->regions, 
                                            data->startIdx, data->endIdx);
    } catch (...) {
        // Handle any exceptions in thread
    }
    
    return 0;
}

// Windows thread procedure for structure scanning
DWORD WINAPI StructureScanThreadProc(LPVOID lpParam) {
    StructureScanData* data = static_cast<StructureScanData*>(lpParam);
    
    try {
        data->processed = 0;
        
        // Scan assigned offset range
        for (int offset = data->startOffset; offset <= data->endOffset; offset += 4) {
            if (offset == 0) continue; // Skip the target itself
            
            DWORD_PTR checkAddr = data->targetAddr + offset;
            auto it = data->pointerMap->find(checkAddr);
            if (it != data->pointerMap->end() && !it->second.empty()) {
                data->results->push_back({checkAddr, offset});
            }
            
            // Update progress counter
            InterlockedIncrement(&data->processed);
            
            // Check for early termination
            if (data->memoryTool && data->memoryTool->interruptSearch) {
                break;
            }
        }
    } catch (...) {
        // Handle any exceptions in thread
    }
    
    return 0;
}

int main() {
    try {
        MemoryTool tool;
        tool.Run();
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}