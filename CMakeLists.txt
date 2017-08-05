cmake_minimum_required(VERSION 3.7)
project(pe_ep_intercept)

set(CMAKE_CXX_STANDARD 11)
set(SOURCE_FILES Main.cpp PePatch.cpp PePatch.h)

include_directories(include)
add_executable(pe_appended ${SOURCE_FILES})