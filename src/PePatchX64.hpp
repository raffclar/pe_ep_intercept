//
// Created by gavxn on 15/08/2017.
//

#ifndef PE_EP_INTERCEPT_PEPATCHX64_HPP
#define PE_EP_INTERCEPT_PEPATCHX64_HPP

#include "PePatch.hpp"

namespace PeEpIntercept {
    class PePatchX64 : public PePatch {
        explicit PePatchX64(std::string &path) : PePatch(path) {}
    };
}


#endif //PE_EP_INTERCEPT_PEPATCHX64_HPP
