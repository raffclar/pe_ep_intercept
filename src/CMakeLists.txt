file(GLOB SOURCE_FILES *.hpp *.cpp)
add_executable(pe_ep_intercept ${SOURCE_FILES})
target_link_libraries(pe_ep_intercept keystone)