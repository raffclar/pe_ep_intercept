cmake_minimum_required(VERSION 3.7)
project(pe_ep_intercept)

set(CMAKE_CXX_STANDARD 11)

set(KEYSTONE_BUILD_STATIC_RUNTIME on)
include_directories(include include/keystone/include)
add_subdirectory(include/keystone)
add_subdirectory(src)