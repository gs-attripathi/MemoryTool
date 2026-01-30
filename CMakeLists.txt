cmake_minimum_required(VERSION 3.16)
project(MemoryTool)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows-specific settings
if(WIN32)
    # Enable static linking to create self-contained executable
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    
    # Link statically with runtime libraries
    if(MSVC)
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
    endif()
    
    # For MinGW/GCC
    if(MINGW)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++ -static")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    endif()
endif()

# Add executable
add_executable(MemoryTool memory_tool.cpp)

# Windows-specific libraries
if(WIN32)
    target_link_libraries(MemoryTool psapi)
endif()

# Compiler-specific optimizations
if(MSVC)
    target_compile_options(MemoryTool PRIVATE /O2 /Ob2 /Oi /Ot /GL)
    target_link_options(MemoryTool PRIVATE /LTCG)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(MemoryTool PRIVATE -O3 -march=native -flto)
    target_link_options(MemoryTool PRIVATE -flto)
endif()

# Set output name
set_target_properties(MemoryTool PROPERTIES OUTPUT_NAME "MemoryTool")