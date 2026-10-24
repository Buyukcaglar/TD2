cmake_minimum_required(VERSION 3.24)
project(TestDrive2 C)

# Top-level build for the Test Drive II reconstruction. The game itself is the vendored Kylofon
# port in port/td2/td2port. Use build.ps1 on Windows; it sets up MSVC and SDL3.

if(MSVC)
    add_compile_options(/utf-8)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# Put the executable (and the SDL3 DLL copied next to it) at the top of the build folder.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_subdirectory(port/td2/td2port)
