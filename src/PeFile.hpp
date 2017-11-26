#ifndef PE_EP_INTERCEPT_PEFILE_HPP
#define PE_EP_INTERCEPT_PEFILE_HPP

#include <string>
#include <memory>
#include <vector>
#include <fstream>

//#include "windows.h"
//#include <imagehlp.h>
//
// http://www.ntinternals.net
// Tomasz Nowak, 2000-2015.
//#include "ntundoc.h"

#include "PeAssembly.hpp"
#include "PeStructs.hpp"

namespace PeEpIntercept {
    class PeFile {
    protected:
        PeArch type = PeArch::unknown;
        std::string path;
        std::fstream file_input;
        std::vector<char> file_buffer;

        uint32_t original_entry_point;
        uint32_t nt_header_signature;
        DosHeader dos_header;
        CoffHeader file_header;
        std::vector<SectionHeader> section_headers;

        static const uint32_t characteristics = scn_code | scn_mem_exe | scn_mem_read | scn_mem_write;

        explicit PeFile(std::string path);

    public:
        std::vector<char> Assemble(const std::string &assembly);

        bool HasSection(const std::string &section_name);

        uint32_t GetOriginalEntryPoint();

        PeArch GetPeArch();

        static PeArch GetPeArch(std::string &path);

        static uint32_t Align(uint32_t num, uint32_t multiple);
    };
}

#endif //PE_EP_INTERCEPT_PEFILE_HPP
