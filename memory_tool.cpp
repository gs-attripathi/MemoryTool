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
        std::cout << " in process memory...\n";
        
        MEMORY_BASIC_INFORMATION mbi;
        DWORD_PTR address = 0;
        
        while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_GUARD) == 0 && 
                (mbi.Protect & PAGE_NOACCESS) == 0) {
                
                SearchInRegion((DWORD_PTR)mbi.BaseAddress, mbi.RegionSize, searchBytes, type);
            }
            
            address = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
        
        std::cout << "Search complete. Found " << searchResults.size() << " results.\n";
        DisplayResults();
    }

    // Search in specific memory region
    void SearchInRegion(DWORD_PTR baseAddr, SIZE_T size, const std::vector<BYTE>& searchBytes, DataType type) {
        const SIZE_T CHUNK_SIZE = 1024 * 1024; // 1MB chunks
        std::vector<BYTE> buffer(CHUNK_SIZE);
        
        for (SIZE_T offset = 0; offset < size; offset += CHUNK_SIZE) {
            SIZE_T readSize = std::min(CHUNK_SIZE, size - offset);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, (LPCVOID)(baseAddr + offset), 
                                buffer.data(), readSize, &bytesRead)) {
                
                for (SIZE_T i = 0; i <= bytesRead - searchBytes.size(); i++) {
                    if (memcmp(buffer.data() + i, searchBytes.data(), searchBytes.size()) == 0) {
                        MemoryResult result;
                        result.address = baseAddr + offset + i;
                        result.value = searchBytes;
                        result.type = type;
                        result.size = searchBytes.size();
                        searchResults.push_back(result);
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
            SIZE_T bytesWritten;
            if (WriteProcessMemory(processHandle, (LPVOID)searchResults[idx].address,
                                 newBytes.data(), newBytes.size(), &bytesWritten)) {
                successCount++;
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

    // Perform the actual pointer search
    void PerformPointerSearch(DWORD_PTR targetAddr, DWORD maxOffset, int maxDepth) {
        // First, find all addresses that point to our target
        std::set<DWORD_PTR> level0Pointers;
        FindDirectPointers(targetAddr, level0Pointers);
        
        // For each module, try to find pointer paths
        for (const auto& module : moduleMap) {
            if (interruptSearch) break;
            
            SearchPointerPaths(module.second, module.first, targetAddr, 
                             level0Pointers, maxOffset, maxDepth, 1);
        }
    }

    // Find direct pointers to target address
    void FindDirectPointers(DWORD_PTR targetAddr, std::set<DWORD_PTR>& pointers) {
        MEMORY_BASIC_INFORMATION mbi;
        DWORD_PTR address = 0;
        
        while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi)) && !interruptSearch) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_GUARD) == 0 && 
                (mbi.Protect & PAGE_NOACCESS) == 0) {
                
                FindPointersInRegion((DWORD_PTR)mbi.BaseAddress, mbi.RegionSize, 
                                   targetAddr, pointers);
            }
            
            address = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
    }

    // Find pointers in specific memory region
    void FindPointersInRegion(DWORD_PTR baseAddr, SIZE_T size, DWORD_PTR targetAddr, 
                            std::set<DWORD_PTR>& pointers) {
        const SIZE_T CHUNK_SIZE = 1024 * 1024;
        std::vector<BYTE> buffer(CHUNK_SIZE);
        
        for (SIZE_T offset = 0; offset < size && !interruptSearch; offset += CHUNK_SIZE) {
            SIZE_T readSize = std::min(CHUNK_SIZE, size - offset);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, (LPCVOID)(baseAddr + offset), 
                                buffer.data(), readSize, &bytesRead)) {
                
                for (SIZE_T i = 0; i <= bytesRead - sizeof(DWORD_PTR); i += sizeof(DWORD_PTR)) {
                    DWORD_PTR value = *(DWORD_PTR*)(buffer.data() + i);
                    if (value == targetAddr) {
                        pointers.insert(baseAddr + offset + i);
                    }
                }
            }
        }
    }

    // Search for pointer paths recursively
    void SearchPointerPaths(DWORD_PTR baseAddr, const std::string& baseName, 
                          DWORD_PTR targetAddr, const std::set<DWORD_PTR>& targetPointers,
                          DWORD maxOffset, int maxDepth, int currentDepth) {
        
        if (currentDepth > maxDepth || interruptSearch) return;
        
        // Try different offsets from base
        for (DWORD offset = 0; offset <= maxOffset && !interruptSearch; offset += 4) {
            DWORD_PTR checkAddr = baseAddr + offset;
            DWORD_PTR value;
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(processHandle, (LPCVOID)checkAddr, 
                                &value, sizeof(value), &bytesRead)) {
                
                if (currentDepth == 1) {
                    // Check if this points directly to target
                    if (value == targetAddr) {
                        PointerPath path;
                        path.baseName = baseName;
                        path.baseAddress = baseAddr;
                        path.offsets.push_back(offset);
                        path.finalAddress = targetAddr;
                        path.depth = 1;
                        pointerResults.push_back(path);
                    }
                    // Check if this points to any of our level 0 pointers
                    else if (targetPointers.find(value) != targetPointers.end()) {
                        PointerPath path;
                        path.baseName = baseName;
                        path.baseAddress = baseAddr;
                        path.offsets.push_back(offset);
                        path.finalAddress = targetAddr;
                        path.depth = 2;
                        
                        // Find the offset from the intermediate pointer to target
                        DWORD_PTR intermediateValue;
                        if (ReadProcessMemory(processHandle, (LPCVOID)value, 
                                            &intermediateValue, sizeof(intermediateValue), &bytesRead)) {
                            if (intermediateValue == targetAddr) {
                                path.offsets.push_back(0);
                            } else {
                                // Try to find the offset
                                for (DWORD intOffset = 0; intOffset <= maxOffset; intOffset += 4) {
                                    DWORD_PTR testAddr = value + intOffset;
                                    DWORD_PTR testValue;
                                    if (ReadProcessMemory(processHandle, (LPCVOID)testAddr, 
                                                        &testValue, sizeof(testValue), &bytesRead)) {
                                        if (testValue == targetAddr) {
                                            path.offsets.push_back(intOffset);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        
                        if (path.offsets.size() == 2) {
                            pointerResults.push_back(path);
                        }
                    }
                }
            }
        }
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
                              std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::system_clock::now().time_since_epoch()).count()) + ".txt";
        
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
        std::cout << "A Cheat Engine-like memory manipulation tool\n\n";
        
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
            std::cout << "3. Search for pointers to address\n";
            std::cout << "4. Exit\n";
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
                    SearchPointers();
                    break;
                case 4:
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