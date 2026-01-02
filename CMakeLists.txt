cmake_minimum_required(VERSION 2.8)

project(l3trans)
add_executable(${PROJECT_NAME} "main.cpp")

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(${PROJECT_NAME} PRIVATE -O3)
endif()
