#ifndef PE_EP_INTERCEPT_PEASSEMBLER_HPP
#define PE_EP_INTERCEPT_PEASSEMBLER_HPP

#include "PeFile.hpp"

namespace Interceptor {
    class Assembler {
    protected:
    public:
        std::vector<char> assemble(PeArch type, const std::string &assembly);
    };
}


#endif //PE_EP_INTERCEPT_PEASSEMBLER_HPP
