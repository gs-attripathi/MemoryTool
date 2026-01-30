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
    int depth;
};

class MemoryTool {
private:
    HANDLE processHandle;
    DWORD processId;
    std::string processName;
    std::vector<MemoryResult> searchResults;
    std::vector<PointerPath> pointerResults;
    std::map<std::string, DWORD_PTR> moduleMap;
    bool interruptSearch;
    
    // Progress tracking for in-place logging
    std::string currentScanType;
    int currentProgress;
    int totalProgress;

public:
    MemoryTool() : processHandle(NULL), processId(0), interruptSearch(false) {}
    
    ~MemoryTool() {
        if (processHandle) {
            CloseHandle(processHandle);
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

        LoadModules();
        std::cout << "Successfully attached to: " << processName 
                 << " (PID: " << processId << " - 0x" << std::hex << processId << std::dec << ")\n";
        return true;
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
                DWORD_PTR val = std::stoull(value, nullptr, 16);
                bytes.resize(sizeof(DWORD_PTR));
                memcpy(bytes.data(), &val, sizeof(DWORD_PTR));
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
            case TYPE_POINTER: return sizeof(DWORD_PTR);
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
                DWORD_PTR val = *(DWORD_PTR*)bytes.data();
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
        std::vector<DWORD_PTR> level0Pointers;
        auto it = pointerMap.find(targetAddr);
        if (it != pointerMap.end()) {
            level0Pointers = it->second;
        }
        
        std::cout << "Found " << level0Pointers.size() << " direct pointers to target.\n\n";
        
        if (level0Pointers.empty()) {
            std::cout << "No direct pointers found. Target might be in stack/heap.\n";
            return;
        }
        
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

    // Build comprehensive pointer map of entire process memory
    void BuildPointerMap(std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap) {
        // First pass: count total regions
        MEMORY_BASIC_INFORMATION mbi;
        DWORD_PTR address = 0;
        int totalRegions = 0;
        
        while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_GUARD) == 0 && 
                (mbi.Protect & PAGE_NOACCESS) == 0 &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                totalRegions++;
            }
            address = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
        
        // Second pass: build pointer map with progress
        StartProgress("POINTER MAP:", totalRegions);
        
        address = 0;
        int regionsScanned = 0;
        int totalPointers = 0;
        
        while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi)) && !interruptSearch) {
            // Only scan committed, readable memory
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_GUARD) == 0 && 
                (mbi.Protect & PAGE_NOACCESS) == 0 &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                
                regionsScanned++;
                int regionPointers = ScanRegionForPointers((DWORD_PTR)mbi.BaseAddress, 
                                                         mbi.RegionSize, pointerMap);
                totalPointers += regionPointers;
                UpdateProgress(regionsScanned);
            }
            
            address = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
        
        FinishProgress("Found " + std::to_string(totalPointers) + " pointers");
    }

    // Scan memory region for all pointers (Cheat Engine approach)
    int ScanRegionForPointers(DWORD_PTR baseAddr, SIZE_T size, 
                             std::map<DWORD_PTR, std::vector<DWORD_PTR>>& pointerMap) {
        const SIZE_T CHUNK_SIZE = 1024 * 1024; // 1MB chunks
        std::vector<BYTE> buffer(CHUNK_SIZE);
        int pointersFound = 0;
        
        for (SIZE_T offset = 0; offset < size && !interruptSearch; offset += CHUNK_SIZE) {
            SIZE_T readSize = std::min(CHUNK_SIZE, size - offset);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, (LPCVOID)(baseAddr + offset), 
                                buffer.data(), readSize, &bytesRead)) {
                
                // Scan every pointer-sized value in this chunk
                for (SIZE_T i = 0; i <= bytesRead - sizeof(DWORD_PTR); i += sizeof(DWORD_PTR)) {
                    DWORD_PTR pointerValue = *(DWORD_PTR*)(buffer.data() + i);
                    DWORD_PTR pointerAddress = baseAddr + offset + i;
                    
                    // Filter out obviously invalid pointers
                    if (IsValidPointer(pointerValue)) {
                        // Add this pointer to our map
                        pointerMap[pointerValue].push_back(pointerAddress);
                        pointersFound++;
                        
                        // Prevent memory explosion
                        if (pointersFound > 1000000) { // 1M pointers max per region
                            return pointersFound;
                        }
                    }
                }
            }
        }
        
        return pointersFound;
    }
    
    // Check if a value looks like a valid pointer
    bool IsValidPointer(DWORD_PTR value) {
        // Basic pointer validation
        if (value < 0x10000) return false; // Too low
        if (value > 0x7FFFFFFFFFFF) return false; // Too high for user space
        if ((value & 0x3) != 0) return false; // Not aligned to 4 bytes
        
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
            SIZE_T bytesRead;
            
            if (!ReadProcessMemory(processHandle, (LPCVOID)checkAddr, 
                                 &value, sizeof(value), &bytesRead)) {
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

    // Display pointer search results
    void DisplayPointerResults() {
        if (pointerResults.empty()) {
            std::cout << "No pointer paths found.\n";
            return;
        }
        
        std::cout << "\nPointer Paths Found:\n";
        std::cout << "Index | Pointer Path | Final Address\n";
        std::cout << "------|--------------|---------------\n";
        
        for (size_t i = 0; i < std::min(pointerResults.size(), (size_t)20); i++) {
            const auto& path = pointerResults[i];
            std::cout << std::setw(5) << i << " | ";
            
            // Format pointer path
            std::cout << "[[" << path.baseName << "+0x" << std::hex << path.offsets[0] << "]";
            for (size_t j = 1; j < path.offsets.size(); j++) {
                std::cout << "+0x" << path.offsets[j];
            }
            std::cout << "] | 0x" << path.finalAddress << std::dec << "\n";
        }
        
        if (pointerResults.size() > 20) {
            std::cout << "... and " << (pointerResults.size() - 20) << " more paths.\n";
        }
        
        // Show how to use the pointer paths
        if (!pointerResults.empty()) {
            std::cout << "\nHow to use pointer paths:\n";
            const auto& example = pointerResults[0];
            std::cout << "Example: " << example.baseName << "+0x" << std::hex << example.offsets[0];
            for (size_t i = 1; i < example.offsets.size(); i++) {
                std::cout << "+0x" << example.offsets[i];
            }
            std::cout << std::dec << "\n";
            std::cout << "This means: Read value at (" << example.baseName << " base + 0x" 
                     << std::hex << example.offsets[0] << std::dec << ")";
            for (size_t i = 1; i < example.offsets.size(); i++) {
                std::cout << ", then add 0x" << std::hex << example.offsets[i] << std::dec;
            }
            std::cout << " to get final address.\n";
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