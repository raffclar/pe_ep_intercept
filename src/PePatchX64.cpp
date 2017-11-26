#include <cstring>
#include "PePatchX64.hpp"

namespace PeEpIntercept {
    PePatchX64::PePatchX64(std::string &path) : PePatch(path) {
        const auto *raw_buffer = file_buffer.data();
        uint32_t first_section = 0;

        if (type == PeArch::x64) {
            auto nt_header = (NtHeaderX64Ptr) &raw_buffer[dos_header.e_lfanew];
            file_header = *(CoffHeaderPtr) &nt_header->coff;
            first_section = dos_header.e_lfanew + sizeof(NtHeaderX64);
            nt_header_signature = nt_header->signature;
            optional_header = *(OptionalHeaderX64Ptr) &nt_header->optional;
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

    void PePatchX64::AddSection(const std::string &name, uint32_t code_size) {
        auto last_section = section_headers.back();
        auto aligned_size = Align(code_size, optional_header.FileAlignment);
        SectionHeader new_section{};

        new_section.Characteristics = characteristics;
        new_section.SizeOfRawData = aligned_size;
        new_section.Misc.VirtualSize = Align(
                aligned_size,
                optional_header.SectionAlignment);
        new_section.PointerToRawData = Align(
                last_section.SizeOfRawData + last_section.PointerToRawData,
                optional_header.FileAlignment);
        new_section.VirtualAddress = Align(
                last_section.Misc.VirtualSize + last_section.VirtualAddress,
                optional_header.SectionAlignment);

        for (size_t i = 0; i < section_name_size; i++) {
            char letter;

            if (i < name.length()) {
                letter = name.at(i);
            } else {
                letter = '\0';
            }

            new_section.Name[i] = static_cast<uint8_t>(letter);
        }

        file_header.NumberOfSections++;
        optional_header.AddressOfEntryPoint = new_section.VirtualAddress;
        optional_header.SizeOfImage =
                new_section.VirtualAddress + new_section.Misc.VirtualSize;
        section_headers.push_back(new_section);
    }

    void PePatchX64::SaveFile(std::string new_path, std::vector<char> code_buffer) {
        if (code_buffer.empty()) {
            throw std::runtime_error("Unable to write empty code section");
        }

        char dos_bytes[sizeof(dos_header)];
        memcpy(dos_bytes, &dos_header, sizeof(dos_header));
        file_input.seekg(0);
        file_input.write(dos_bytes, sizeof(dos_header));

        NtHeaderX64 nt_headers{
                nt_header_signature,
                file_header,
                optional_header};

        char nt_bytes[sizeof(nt_headers)];
        memcpy(nt_bytes, &nt_headers, sizeof(nt_headers));
        file_input.seekg(dos_header.e_lfanew, std::ios_base::beg);
        file_input.write(nt_bytes, sizeof(nt_headers));
        uint32_t address = dos_header.e_lfanew + sizeof(nt_headers);

        for (auto &section_header : section_headers) {
            char hdr_bytes[sizeof(section_header)];
            memcpy(hdr_bytes, &section_header, sizeof(section_header));
            file_input.seekg(address);
            file_input.write(hdr_bytes, sizeof(section_header));
            address += sizeof(section_header);
        }

        auto new_section = &section_headers.back();
        uint32_t code_position = new_section->PointerToRawData;
        file_input.seekg(code_position);

        // Padding might be required otherwise the loader will fail
        // when loading the executable
        while (code_buffer.size() < new_section->SizeOfRawData) {
            code_buffer.push_back(0);
        }

        file_input.write(code_buffer.data(), code_buffer.size());
    }
}
