cmake_minimum_required(VERSION 3.15)
project(DqxNative C CXX)

# All targets must be 32-bit to match DQXGame.exe.
# Pass -A Win32 (MSVC) or -DCMAKE_C_FLAGS=-m32 (MinGW) at configure time.

set(COMMON_DEFS WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)

# --- LocaleHook.dll ---
add_library(LocaleHook SHARED LocaleHook.c)
set_target_properties(LocaleHook PROPERTIES
    PREFIX ""
    OUTPUT_NAME "LocaleHook"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)
target_compile_definitions(LocaleHook PRIVATE ${COMMON_DEFS})
target_link_libraries(LocaleHook PRIVATE kernel32 user32 imm32)

add_custom_command(TARGET LocaleHook POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:LocaleHook> "${CMAKE_CURRENT_SOURCE_DIR}/LocaleHook.dll"
)

# --- PacketWarden.dll ---
# Hooks ParseNetworkPacket in DQXGame.exe and forwards packets to the c# host
# over a named pipe. Replaces the python+frida packet_warden hook. Built as c++
# because __thiscall on a function-pointer typedef is a c++-only extension
# under MSVC; the rest of the source is plain c-compatible.
add_library(PacketWarden SHARED PacketWarden.cpp)
set_target_properties(PacketWarden PROPERTIES
    PREFIX ""
    OUTPUT_NAME "PacketWarden"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)
target_compile_definitions(PacketWarden PRIVATE ${COMMON_DEFS})
target_link_libraries(PacketWarden PRIVATE kernel32 user32 psapi)

add_custom_command(TARGET PacketWarden POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:PacketWarden> "${CMAKE_CURRENT_SOURCE_DIR}/PacketWarden.dll"
)
