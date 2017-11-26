#ifndef PE_EP_INTERCEPT_PEASSEMBLY_HPP
#define PE_EP_INTERCEPT_PEASSEMBLY_HPP

#include <string>

namespace PeEpIntercept {
    enum class PeArch {
        x86,
        x64,
        unknown
    };

    std::string EntryRedirectAssemblyX64(uint32_t oep);

    std::string EntryRedirectAssemblyX86(uint32_t oep);
}


#endif //PE_EP_INTERCEPT_PEASSEMBLY_HPP
