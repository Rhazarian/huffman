cmake_minimum_required(VERSION 3.0)
project(huffman)

include_directories(${huffman_SOURCE_DIR})

add_executable(huffman-util main.cpp)
add_executable(huffman-testing huffman_testing.cpp
        gtest/gtest-all.cc
        gtest/gtest.h
        gtest/gtest_main.cc)


add_library(huffman SHARED lib/huffman.h lib/huffman.cpp)
include_directories(lib)

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++17 -pedantic")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_GLIBCXX_DEBUG")
endif()

target_link_libraries(huffman-util huffman)
target_link_libraries(huffman-testing huffman -lpthread)