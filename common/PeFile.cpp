#include "PeFile.hpp"
#include "PeStructs.hpp"
#include <cinttypes>
#include <iostream>

namespace Interceptor {
    PeFile::PeFile(std::vector<char> file_contents) : file_data(file_contents) {
        const auto *raw_buffer = file_contents.data();
        dos_header = *(DosHeaderPtr) raw_buffer;

        if (dos_header.e_magic[0] != 'M' || dos_header.e_magic[1] != 'Z') {
            throw std::runtime_error("could not executable read headers");
        }

        size_t machine_offset = dos_header.e_lfanew + sizeof(uint32_t);
        auto machine = static_cast<uint16_t>((raw_buffer[machine_offset + 1] << 8) + raw_buffer[machine_offset]);

        switch (machine) {
            case 0x014c:
                type = PeArch::x86;
                break;
            case 0x8664:
                type = PeArch::x64;
                break;
            default:
                throw std::runtime_error("executable type is not x86 or x64");
        }

        nt_header_signature = 0;
        entry_point = 0;
        file_header = {};

        uint32_t first_section = 0;

        if (type == PeArch::x64) {
            auto nt_header = (NtHeaderX64Ptr) &raw_buffer[dos_header.e_lfanew];
            file_header = *(CoffHeaderPtr) &nt_header->coff;
            first_section = dos_header.e_lfanew + sizeof(NtHeaderX64);
            nt_header_signature = nt_header->signature;
            optional_header_x64 = *(OptionalHeaderX64Ptr) &nt_header->optional;
            entry_point = optional_header_x64.AddressOfEntryPoint;
        } else {
            auto nt_header = (NtHeaderX86Ptr) &raw_buffer[dos_header.e_lfanew];
            file_header = *(CoffHeaderPtr) &nt_header->coff;
            first_section = dos_header.e_lfanew + sizeof(NtHeaderX86);
            nt_header_signature = nt_header->signature;
            optional_header_x86 = *(OptionalHeaderX86Ptr) &nt_header->optional;
            entry_point = optional_header_x86.AddressOfEntryPoint;
        }

        if (nt_header_signature != 0x4550) {
            throw std::runtime_error("This is not a portable executable");
        }

        for (int i = 0; i < file_header.NumberOfSections; i++) {
            uint32_t section_index = i * sizeof(SectionHeader);
            uint32_t next_section = first_section + section_index;
            auto hdr = *(SectionHeaderPtr) &raw_buffer[next_section];
            section_headers.push_back(hdr);
        }

        auto rest_of_data = first_section;
        auto count = static_cast<uint32_t>(section_headers.size());
        rest_of_data += count * sizeof(SectionHeader);

        // Excludes headers since we already have the initialised structs
        auto data_start = file_contents.begin() + rest_of_data;
        file_data.assign(data_start, file_contents.end());
    }

    bool PeFile::hasSection(const std::string &section_name) {
        for (auto &section : section_headers) {
            if (reinterpret_cast<char *>(section.Name) == section_name) {
                return true;
            }
        }

        return false;
    }

    PeArch PeFile::getPeArch() {
        return type;
    }

    DosHeader PeFile::getDosHeader() {
        return dos_header;
    }

    CoffHeader PeFile::getFileHeader() {
        return file_header;
    }

    OptionalHeaderX64 PeFile::getOptionalHeaderX64() {
        return optional_header_x64;
    }

    OptionalHeaderX86 PeFile::getOptionalHeaderX86() {
        return optional_header_x86;
    }

    std::vector<SectionHeader> PeFile::getSectionHeaders() {
        return section_headers;
    }

    uint32_t PeFile::getEntryPoint(){
        return entry_point;
    }

    void PeFile::addSectionHeader(SectionHeader header) {
        section_headers.push_back(header);
    }

    void PeFile::setDosHeader(DosHeader dos_header) {
        this->dos_header = dos_header;
    }

    void PeFile::setFileHeader(CoffHeader file_header) {
        this->file_header = file_header;
    }

    void PeFile::setOptionalHeaderX64(OptionalHeaderX64 optional_header) {
        this->optional_header_x64 = optional_header;
    }

    void PeFile::setOptionalHeaderX86(OptionalHeaderX86 optional_header) {
        this->optional_header_x86 = optional_header;
    }

    void PeFile::appendFileData(std::vector<char> new_data) {
        file_data.insert(file_data.end(), new_data.begin(), new_data.end());
    }

    std::vector<char> PeFile::getFileContents() {
        std::vector<char> file_contents;

        // DOS header
        size_t i = 0;
        char dos_header_bytes[sizeof(dos_header)];

        memcpy(&dos_header_bytes[i], &dos_header.e_magic, sizeof(dos_header.e_magic));
        i += sizeof(dos_header.e_magic);
        memcpy(&dos_header_bytes[i], &dos_header.e_cblp, sizeof(dos_header.e_cblp));
        i += sizeof(dos_header.e_cblp);
        memcpy(&dos_header_bytes[i], &dos_header.e_cp, sizeof(dos_header.e_cp));
        i += sizeof(dos_header.e_cp);
        memcpy(&dos_header_bytes[i], &dos_header.e_crlc, sizeof(dos_header.e_crlc));
        i += sizeof(dos_header.e_crlc);
        memcpy(&dos_header_bytes[i], &dos_header.e_cparhdr, sizeof(dos_header.e_cparhdr));
        i += sizeof(dos_header.e_cparhdr);
        memcpy(&dos_header_bytes[i], &dos_header.e_minalloc, sizeof(dos_header.e_minalloc));
        i += sizeof(dos_header.e_minalloc);
        memcpy(&dos_header_bytes[i], &dos_header.e_maxalloc, sizeof(dos_header.e_maxalloc));
        i += sizeof(dos_header.e_maxalloc);
        memcpy(&dos_header_bytes[i], &dos_header.e_ss, sizeof(dos_header.e_ss));
        i += sizeof(dos_header.e_ss);
        memcpy(&dos_header_bytes[i], &dos_header.e_sp, sizeof(dos_header.e_sp));
        i += sizeof(dos_header.e_sp);
        memcpy(&dos_header_bytes[i], &dos_header.e_csum, sizeof(dos_header.e_csum));
        i += sizeof(dos_header.e_csum);
        memcpy(&dos_header_bytes[i], &dos_header.e_ip, sizeof(dos_header.e_ip));
        i += sizeof(dos_header.e_ip);
        memcpy(&dos_header_bytes[i], &dos_header.e_cs, sizeof(dos_header.e_cs));
        i += sizeof(dos_header.e_cs);
        memcpy(&dos_header_bytes[i], &dos_header.e_lfarlc, sizeof(dos_header.e_lfarlc));
        i += sizeof(dos_header.e_lfarlc);
        memcpy(&dos_header_bytes[i], &dos_header.e_ovno, sizeof(dos_header.e_ovno));
        i += sizeof(dos_header.e_ovno);
        memcpy(&dos_header_bytes[i], &dos_header.e_res, sizeof(dos_header.e_res));
        i += sizeof(dos_header.e_res);
        memcpy(&dos_header_bytes[i], &dos_header.e_oemid, sizeof(dos_header.e_oemid));
        i += sizeof(dos_header.e_oemid);
        memcpy(&dos_header_bytes[i], &dos_header.e_oeminfo, sizeof(dos_header.e_oeminfo));
        i += sizeof(dos_header.e_oeminfo);
        memcpy(&dos_header_bytes[i], &dos_header.e_res2, sizeof(dos_header.e_res2));
        i += sizeof(dos_header.e_res2);
        memcpy(&dos_header_bytes[i], &dos_header.e_lfanew, sizeof(dos_header.e_lfanew));
        i += sizeof(dos_header.e_lfanew);

        file_contents.insert(file_contents.end(), dos_header_bytes, dos_header_bytes + i);

        NtHeaderX64 nt_header {
                nt_header_signature,
                file_header,
                optional_header_x64
        };

        // NT header
        //
//        auto *nt_header_bytes = static_cast<char*>(static_cast<void*>(&nt_header));
//        length = sizeof(dos_header_bytes);
//        file_contents.insert(file_contents.end(), nt_header_bytes, nt_header_bytes + length);

        // Section headers
        //
        uint32_t section_offset = dos_header.e_lfanew + sizeof(nt_header);

//        for (auto &section_header : section_headers) {
//            auto section_header_bytes = static_cast<char*>(static_cast<void*>(&section_header));
//            length = sizeof(section_header);
//            file_contents.insert(file_contents.end(), section_header_bytes, section_header_bytes + length);
//            section_offset += sizeof(section_header);
//        }

        // Rest of executable
        //
        auto new_section = &section_headers.back();
        uint32_t code_start = new_section->PointerToRawData;
        file_contents.insert(file_contents.end(), file_data.begin(), file_data.end());

        return file_contents;
    }
} // namespace Interceptor
