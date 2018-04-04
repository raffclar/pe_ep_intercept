add_executable(pe_ep_intercept ${COMMON_SOURCE_FILES} Main.cpp ../common/PePatch.cpp ../common/PePatch.hpp)
set_property(TARGET pe_ep_intercept PROPERTY CXX_STANDARD 14)
set_property(TARGET pe_ep_intercept PROPERTY CXX_STANDARD_REQUIRED ON)
target_link_libraries(pe_ep_intercept keystone)