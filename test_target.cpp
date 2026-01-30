#include <iostream>
#include <windows.h>

int main() {
    // Create some test values in memory
    int health = 100;
    float speed = 5.5f;
    double score = 12345.67;
    char name[] = "TestPlayer";
    
    std::cout << "=== Test Target Process ===" << std::endl;
    std::cout << "This program creates test values for the Memory Tool" << std::endl;
    std::cout << "Process Name: test_target.exe" << std::endl;
    std::cout << std::endl;
    
    while (true) {
        std::cout << "Health: " << health << " (int)" << std::endl;
        std::cout << "Speed: " << speed << " (float)" << std::endl;
        std::cout << "Score: " << score << " (double)" << std::endl;
        std::cout << "Name: " << name << " (string)" << std::endl;
        std::cout << "Memory addresses:" << std::endl;
        std::cout << "  Health at: 0x" << std::hex << (uintptr_t)&health << std::dec << std::endl;
        std::cout << "  Speed at:  0x" << std::hex << (uintptr_t)&speed << std::dec << std::endl;
        std::cout << "  Score at:  0x" << std::hex << (uintptr_t)&score << std::dec << std::endl;
        std::cout << "  Name at:   0x" << std::hex << (uintptr_t)&name << std::dec << std::endl;
        std::cout << std::endl;
        std::cout << "Use MemoryTool to search for these values and modify them!" << std::endl;
        std::cout << "Press Ctrl+C to exit..." << std::endl;
        std::cout << "----------------------------------------" << std::endl;
        
        Sleep(3000); // Wait 3 seconds
    }
    
    return 0;
}