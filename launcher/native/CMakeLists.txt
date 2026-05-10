cmake_minimum_required(VERSION 3.15)
project(DqxLocale C)

# Both targets must be 32-bit to match DQXGame.exe.
# Pass -A Win32 (MSVC) or -DCMAKE_C_FLAGS=-m32 (MinGW) at configure time.

set(COMMON_DEFS WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)

# --- LocaleHook.dll ---
add_library(LocaleHook SHARED LocaleHook.c)
set_target_properties(LocaleHook PROPERTIES PREFIX "" OUTPUT_NAME "LocaleHook")
target_compile_definitions(LocaleHook PRIVATE ${COMMON_DEFS})
target_link_libraries(LocaleHook PRIVATE kernel32)

# Copy output to native/ after build so the .csproj Content item picks it up
add_custom_command(TARGET LocaleHook POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:LocaleHook> "${CMAKE_CURRENT_SOURCE_DIR}/LocaleHook.dll"
)
