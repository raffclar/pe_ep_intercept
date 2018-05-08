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
        std::vector<char> section_data;

        Architecture type = Architecture::unknown;
        uint32_t entry_point;

        // In order of PE format
        RawHeaders::DosHeader dos_header;
        uint32_t nt_header_signature;
        RawHeaders::CoffHeader coff_header;
        RawHeaders::OptionalHeaderX64 optional_header_x64;
        RawHeaders::OptionalHeaderX86 optional_header_x86;
        std::vector<RawHeaders::SectionHeader> section_headers;
    public:
        explicit PeFile(std::fstream &file_stream);

        bool hasSection(const std::string &section_name);

        uint32_t getEntryPoint();

        Architecture getPeArch();

        RawHeaders::DosHeader getDosHeader();

        RawHeaders::CoffHeader getFileHeader();

        RawHeaders::OptionalHeaderX64 getOptionalHeaderX64();

        RawHeaders::OptionalHeaderX86 getOptionalHeaderX86();

        std::vector<RawHeaders::SectionHeader> getSectionHeaders();

        void addSectionHeader(RawHeaders::SectionHeader header);

        void setDosHeader(RawHeaders::DosHeader dos_header);

        void setFileHeader(RawHeaders::CoffHeader file_header);

        void setOptionalHeaderX64(RawHeaders::OptionalHeaderX64 optional_header);

        void setOptionalHeaderX86(RawHeaders::OptionalHeaderX86 optional_header);

        void appendFileData(std::vector<char> new_data);

        void write(std::fstream &file);
    };
}


#endif //PE_EP_INTERCEPT_PEFILE_HPP
