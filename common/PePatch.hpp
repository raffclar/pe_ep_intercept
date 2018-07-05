#ifndef PE_EP_INTERCEPT_PEPATCH_HPP
#define PE_EP_INTERCEPT_PEPATCH_HPP

#include <utility>

#include "Assembler.hpp"
#include "PeFile.hpp"
#include "PeStructs.hpp"

namespace Interceptor {
    using namespace Interceptor::RawHeaders;

    class PePatch {
    protected:
        static const uint32_t section_rights = scn_code | scn_mem_exe | scn_mem_read | scn_mem_write;
        Assembler assembler;
        PeFile file;
        uint32_t align(uint32_t num, uint32_t multiple);
        virtual void addSection(const std::string &name) = 0;
        virtual PeFile patch(const std::string &section) = 0;
    public:
        PePatch(const Assembler &assembler, PeFile file) : assembler(assembler), file(std::move(file)) {};
    };
}


#endif //PE_EP_INTERCEPT_PEPATCH_HPP
