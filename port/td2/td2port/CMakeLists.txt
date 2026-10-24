cmake_minimum_required(VERSION 3.24)
project(td2port C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# The port runs TD2EGA.EXE's image; CGA and Hercules are run-time graphics backends.

# The top-level build adds SDL3 from source (static); a standalone build uses an installed SDL3.
if(NOT TARGET SDL3::SDL3)
    find_package(SDL3 REQUIRED CONFIG)
endif()

file(GLOB_RECURSE TD_SOURCES CONFIGURE_DEPENDS src/*.c)

add_executable(td2port WIN32 ${TD_SOURCES} td2port.rc)
target_include_directories(td2port PRIVATE src)
target_link_libraries(td2port PRIVATE SDL3::SDL3)
if(MSVC)
    target_compile_options(td2port PRIVATE /W3)
else()
    # The memory model reads multi-byte values through byte pointers (see src/mem.h).
    target_compile_options(td2port PRIVATE -Wall -Wextra -Wno-unused-parameter -fno-strict-aliasing)
    # Game strings are copied out of mem[] into fixed buffers with snprintf; truncation is intended.
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        target_compile_options(td2port PRIVATE -Wno-format-truncation)
    endif()
endif()
if(MSVC)
    # A windowed app that still starts at main(); the manifest comes from td2port.rc.
    target_link_options(td2port PRIVATE /ENTRY:mainCRTStartup /MANIFEST:NO)
endif()
if(WIN32 AND TARGET SDL3::SDL3-shared)
    add_custom_command(TARGET td2port POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:td2port> $<TARGET_FILE_DIR:td2port>
        COMMAND_EXPAND_LISTS)
endif()
