#ifndef PE_EP_INTERCEPT_PEFILE_HPP
#define PE_EP_INTERCEPT_PEFILE_HPP

#include <string>
#include <memory>
#include <vector>
#include <fstream>

#include "Assembly.hpp"
#include "PeStructs.hpp"

namespace Interceptor {
    class PeFile {
    protected:
        std::vector<char> file_data;

        PeArch type = PeArch::unknown;
        uint32_t entry_point;
        uint32_t nt_header_signature;

        DosHeader dos_header;
        CoffHeader file_header;
        OptionalHeaderX64 optional_header_x64;
        OptionalHeaderX86 optional_header_x86;

        std::vector<SectionHeader> section_headers;
    public:
        PeFile(std::vector<char> file_contents);

        bool hasSection(const std::string &section_name);

        uint32_t getEntryPoint();

        PeArch getPeArch();

        DosHeader getDosHeader();

        CoffHeader getFileHeader();

        OptionalHeaderX64 getOptionalHeaderX64();

        OptionalHeaderX86 getOptionalHeaderX86();

        std::vector<SectionHeader> getSectionHeaders();

        void addSectionHeader(SectionHeader header);

        void setDosHeader(DosHeader dos_header);

        void setFileHeader(CoffHeader file_header);

        void setOptionalHeaderX64(OptionalHeaderX64 optional_header);

        void setOptionalHeaderX86(OptionalHeaderX86 optional_header);

        void appendFileData(std::vector<char> new_data);

        std::vector<char> getFileContents();
    };
}


#endif //PE_EP_INTERCEPT_PEFILE_HPP
