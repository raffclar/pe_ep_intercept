//
// Created by gavxn on 15/08/2017.
//

#ifndef PE_EP_INTERCEPT_PEPATCHX86_HPP
#define PE_EP_INTERCEPT_PEPATCHX86_HPP

#include "PePatch.hpp"

namespace PeEpIntercept {
    class PePatchX86 : public PePatch {
        explicit PePatchX86(std::string &path) : PePatch(path) {}
    };
}


#endif //PE_EP_INTERCEPT_PEPATCHX86_HPP
