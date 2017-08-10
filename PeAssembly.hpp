//
// Created by gavxn on 10/08/2017.
//

#ifndef PE_EP_INTERCEPT_PEASSEMBLY_HPP
#define PE_EP_INTERCEPT_PEASSEMBLY_HPP

#include <string>

namespace PeEpIntercept {
    typedef enum class {
        x86,
        x64,
        unknown
    } PeArch;

    std::string EntryRedirectAssemblyX64(uint32_t oep);

    std::string EntryRedirectAssemblyX86(uint32_t oep);
}

#endif //PE_EP_INTERCEPT_PEASSEMBLY_HPP
