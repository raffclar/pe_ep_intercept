cmake_minimum_required(VERSION 3.6)
project(pe_ep_intercept)
# Keystone
set(KEYSTONE_BUILD_STATIC_RUNTIME on)
include_directories(include include/keystone/include)

file(GLOB COMMON_SOURCE_FILES common/*.hpp common/*.cpp)

# Sources
add_subdirectory(include/keystone)
add_subdirectory(src)
add_subdirectory(tests)