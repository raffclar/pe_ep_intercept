# Boost
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME ON)

find_package(Boost COMPONENTS system filesystem REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

message(STATUS "Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost_LIBRARIES: ${Boost_LIBRARIES}")
message(STATUS "Boost_VERSION: ${Boost_VERSION}")

add_executable(pe_ep_intercept_tests ${COMMON_SOURCE_FILES} Main.cpp)
target_link_libraries(pe_ep_intercept_tests ${Boost_LIBRARIES} Boost::disable_autolinking keystone)
set_target_properties(pe_ep_intercept_tests PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

# Set standards
set_property(TARGET pe_ep_intercept_tests PROPERTY CXX_STANDARD 14)
set_property(TARGET pe_ep_intercept_tests PROPERTY CXX_STANDARD_REQUIRED ON)

