cmake_minimum_required(VERSION 3.22.1)
project(wow_emu_v2 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_executable(wow_emu_v2
    src/main.cpp
    src/emu_runtime.cpp
    src/pe_loader.cpp
    src/shim_api.cpp
)

find_library(log-lib log)
find_library(unicorn-lib unicorn)
target_link_libraries(wow_emu_v2 ${unicorn-lib})
if(log-lib)
    target_link_libraries(wow_emu_v2 ${log-lib})
endif()
