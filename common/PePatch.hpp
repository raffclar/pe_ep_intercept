#ifndef PE_EP_INTERCEPT_PEPATCH_HPP
#define PE_EP_INTERCEPT_PEPATCH_HPP

#include "Assembler.hpp"
#include "PeFile.hpp"

namespace Interceptor {
    class PePatch {
    protected:
        static const uint32_t section_rights = scn_code | scn_mem_exe | scn_mem_read | scn_mem_write;
        Assembler assembler;
        PeFile file;
        uint32_t Align(uint32_t num, uint32_t multiple);
    public:
        PePatch(const Assembler &assembler, const PeFile &file) : assembler(assembler), file(file) {};
    };
}


#endif //PE_EP_INTERCEPT_PEPATCH_HPP
