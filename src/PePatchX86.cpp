//
// Created by gavxn on 15/08/2017.
//

#include "PePatchX86.hpp"

namespace PeEpIntercept {
    PePatchX86::PePatchX86(std::string &path) : PeFile(path) {
        const auto *raw_buffer = file_buffer.data();
        uint32_t first_section = 0;

        if (type == PeArch::x86) {
            auto nt_header = (NtHeaderX86Ptr) &raw_buffer[dos_header.e_lfanew];
            file_header = *(CoffHeaderPtr) &nt_header->coff;
            first_section = dos_header.e_lfanew + sizeof(NtHeaderX86);
            nt_header_signature = nt_header->signature;
            optional_header = *(OptionalHeaderX86Ptr) &nt_header->optional;
        }

        if (nt_header_signature != 0x4550) {
            throw std::runtime_error("This is not a portable executable");
        }

        original_entry_point = optional_header.AddressOfEntryPoint;

        for (uint32_t i = 0; i < file_header.NumberOfSections; i++) {
            uint32_t section_index = i * sizeof(SectionHeader);
            uint32_t next_section = first_section + section_index;
            auto hdr = *(SectionHeaderPtr) &raw_buffer[next_section];
            section_headers.push_back(hdr);
        }

        auto rest_of_data = first_section;
        auto count = static_cast<uint32_t>(section_headers.size());
        rest_of_data += count * sizeof(SectionHeader);

        // Excludes headers since we already have the initialised structs
        auto data_start = file_buffer.begin() + rest_of_data;
        this->file_buffer.assign(data_start, file_buffer.end());
    }

    void PePatchX86::SaveFile(std::string new_path, std::vector<char> code_buffer) {

    }

    void PePatchX86::AddSection(const std::string &name, uint32_t code_size) {

    }
}
