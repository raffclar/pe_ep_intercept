#ifndef PE_EP_INTERCEPT_ASSEMBLY_HPP
#define PE_EP_INTERCEPT_ASSEMBLY_HPP

#include <string>

namespace Interceptor {
    enum class Architecture {
        x86,
        x64,
        unknown
    };

    std::string entryRedirectAssemblyX64(uint32_t oep);

    std::string entryRedirectAssemblyX86(uint32_t oep);
}


#endif //PE_EP_INTERCEPT_ASSEMBLY_HPP
