cmake_minimum_required(VERSION 3.5)

project(tiny-sniffer VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

if (MSVC)
    add_compile_options(/utf-8)
endif()

add_subdirectory(core)
add_subdirectory(gui)
add_subdirectory(test)
