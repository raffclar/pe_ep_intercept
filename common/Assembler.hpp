#ifndef PE_EP_INTERCEPT_ASSEMBLER_HPP
#define PE_EP_INTERCEPT_ASSEMBLER_HPP

#include "PeFile.hpp"

namespace Interceptor {
    class Assembler {
    protected:
    public:
        std::vector<char> assemble(Architecture type, const std::string &assembly);
    };
}


#endif //PE_EP_INTERCEPT_ASSEMBLER_HPP
