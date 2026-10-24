cmake_minimum_required(VERSION 3.24)
project(TestDrive2 C)

# Top-level build for the Test Drive II reconstruction. The game itself is the vendored Kylofon
# port in port/td2/td2port. Use build.ps1 on Windows; it sets up MSVC and SDL3.

if(MSVC)
    add_compile_options(/utf-8)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# Put the executable at the top of the build folder.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# A single portable exe: SDL3, built here from its source, and the C runtime are linked statically.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(TD2_SDL_SOURCE "" CACHE PATH "SDL3 source tree (the release tarball, unpacked)")
if(NOT EXISTS "${TD2_SDL_SOURCE}/CMakeLists.txt")
    message(FATAL_ERROR "TD2_SDL_SOURCE must point at the SDL3 source tree")
endif()
set(SDL_SHARED OFF CACHE BOOL "" FORCE)
set(SDL_STATIC ON CACHE BOOL "" FORCE)
set(SDL_TEST_LIBRARY OFF CACHE BOOL "" FORCE)
set(SDL_DISABLE_INSTALL ON CACHE BOOL "" FORCE)
add_subdirectory(${TD2_SDL_SOURCE} ${CMAKE_BINARY_DIR}/sdl3 EXCLUDE_FROM_ALL SYSTEM)

add_subdirectory(port/td2/td2port)

# td2diff.dll: the port's game and platform code with a stub host, for tools/diffharness.
set(TD2_SRC ${CMAKE_SOURCE_DIR}/port/td2/td2port/src)
file(GLOB_RECURSE TD2_CORE_SOURCES CONFIGURE_DEPENDS ${TD2_SRC}/*.c)
list(REMOVE_ITEM TD2_CORE_SOURCES ${TD2_SRC}/main.c ${TD2_SRC}/host.c)
list(FILTER TD2_CORE_SOURCES EXCLUDE REGEX "/src/app/")      # the app's own UI around the game
add_library(td2diff SHARED ${TD2_CORE_SOURCES} tools/diffharness/host_stub.c tools/diffharness/adapters.c)
target_include_directories(td2diff PRIVATE ${TD2_SRC} tools/diffharness)
target_link_libraries(td2diff PRIVATE SDL3::SDL3)
set_target_properties(td2diff PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
if(MSVC)
    target_compile_options(td2diff PRIVATE /W3)
endif()
