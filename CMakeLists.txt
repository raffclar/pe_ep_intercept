cmake_minimum_required(VERSION 3.7)
project(pe_ep_intercept)

set(CMAKE_CXX_STANDARD 11)

set(KEYSTONE_BUILD_STATIC_RUNTIME on)
include_directories(include include/keystone/include)
add_subdirectory(include/keystone)

set(SOURCE_FILES Main.cpp PePatch.cpp PePatch.hpp PeAssembly.cpp PeAssembly.hpp)

add_executable(pe_ep_intercept ${SOURCE_FILES})
target_link_libraries(pe_ep_intercept keystone)