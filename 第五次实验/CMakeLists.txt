cmake_minimum_required(VERSION 3.13)

project(seal_bfv_conv2d_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(SEAL 4.1 REQUIRED)

add_executable(seal_bfv_conv2d seal_bfv_conv2d.cpp)
target_link_libraries(seal_bfv_conv2d PRIVATE SEAL::seal)
