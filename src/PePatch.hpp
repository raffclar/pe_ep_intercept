#ifndef PE_EP_INTERCEPT_PEPATCH_HPP
#define PE_EP_INTERCEPT_PEPATCH_HPP

#include <string>
#include <memory>
#include <vector>
#include <fstream>

#include "windows.h"
#include <imagehlp.h>

// http://www.ntinternals.net
// Tomasz Nowak, 2000-2015.
#include "ntundoc.h"

#include "PeAssembly.hpp"

namespace PeEpIntercept {
    class PePatch {
    private:
        PeArch type = PeArch::unknown;
        std::string path;
        std::fstream file_input;
        std::vector<char> file_buffer;

        uint32_t original_entry_point;
        uint32_t nt_header_signature;
        IMAGE_DOS_HEADER dos_header;
        IMAGE_FILE_HEADER file_header;
        IMAGE_OPTIONAL_HEADER optional_header;
        std::vector<IMAGE_SECTION_HEADER> section_headers;
    public:
        explicit PePatch(std::string path);

        std::vector<char> Assemble(const std::string &assembly);

        bool HasSection(const std::string &section_name);

        void AddSection(const std::string &name, uint32_t code_size);

        void SaveFile(std::string new_path, std::vector<char> code_buffer);

        uint32_t GetOriginalEntryPoint();

        PeArch GetPeArch();
    };
}

#endif //PE_EP_INTERCEPT_PEPATCH_HPP
