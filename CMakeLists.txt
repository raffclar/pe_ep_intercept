cmake_minimum_required(VERSION 3.6)
project(pe_ep_intercept)

set(KEYSTONE_BUILD_STATIC_RUNTIME on)
include_directories(include include/keystone/include)
add_subdirectory(include/keystone)
add_subdirectory(src)