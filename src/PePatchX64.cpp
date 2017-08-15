//
// Created by gavxn on 15/08/2017.
//

#include "PePatchX64.hpp"

namespace PeEpIntercept {
    PePatch::PePatch(std::string path) : path(path) {
        file_input.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        file_input.open(path, std::ios::binary |
                              std::ifstream::ate |
                              std::fstream::in |
                              std::fstream::out);
        std::streamsize size = file_input.tellg();
        file_input.seekg(0, std::ios::beg);

        if (size <= 0) {
            throw std::runtime_error("could not get file size");
        }

        std::vector<char> file_buffer((uint32_t) size);

        if (!file_input.read(file_buffer.data(), size)) {
            throw std::runtime_error("could not read file");
        }

        const auto *raw_buffer = file_buffer.data();

        // Portable Executable headers
        dos_header = *(PIMAGE_DOS_HEADER) raw_buffer;

        if (dos_header.e_magic != 0x5a4d) {
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

        uint32_t first_section = 0;

        if (type == PeArch::x86) {
            auto nt_header = (PIMAGE_NT_HEADERS32) &raw_buffer[dos_header.e_lfanew];
            file_header = *(PIMAGE_FILE_HEADER) &nt_header->FileHeader;
            first_section = dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS32);
            nt_header_signature = nt_header->Signature;
            //optional_header = *(PIMAGE_OPTIONAL_HEADER32) &nt_header->OptionalHeader;
        } else if (type == PeArch::x64) {
            auto nt_header = (PIMAGE_NT_HEADERS64) &raw_buffer[dos_header.e_lfanew];
            file_header = *(PIMAGE_FILE_HEADER) &nt_header->FileHeader;
            first_section = dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
            nt_header_signature = nt_header->Signature;
            optional_header = *(PIMAGE_OPTIONAL_HEADER64) &nt_header->OptionalHeader;
        }

        if (nt_header_signature != 0x4550) {
            throw std::runtime_error("This is not a portable executable");
        }

        original_entry_point = optional_header.AddressOfEntryPoint;

        for (uint32_t i = 0; i < file_header.NumberOfSections; i++) {
            uint32_t section_index = i * sizeof(IMAGE_SECTION_HEADER);
            uint32_t next_section = first_section + section_index;
            auto hdr = *(PIMAGE_SECTION_HEADER) &raw_buffer[next_section];
            section_headers.push_back(hdr);
        }

        auto rest_of_data = first_section;
        auto count = static_cast<uint32_t>(section_headers.size());
        rest_of_data += count * sizeof(IMAGE_SECTION_HEADER);

        // Excludes headers since we already have the initialised structs
        auto data_start = file_buffer.begin() + rest_of_data;
        this->file_buffer.assign(data_start, file_buffer.end());
    }
}
