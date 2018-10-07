#include "PePatch.hpp"

namespace Interceptor {
    uint32_t PePatch::Align(uint32_t num, uint32_t multiple) {
        return ((num + multiple - 1) / multiple) * multiple;
    }
}