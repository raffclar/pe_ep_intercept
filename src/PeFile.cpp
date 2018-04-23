#include "PeFile.hpp"
#include <cinttypes>
#include <iostream>

namespace PeEpIntercept {
    PeFile::PeFile(std::string path) {
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

        file_buffer.resize((uint32_t) size);

        if (!file_input.read(file_buffer.data(), size)) {
            throw std::runtime_error("could not read file");
        }

        const auto *raw_buffer = file_buffer.data();
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
        original_entry_point = 0;
        file_header = {};
    }

    bool PeFile::HasSection(const std::string &section_name) {
        for (auto &section : section_headers) {
            if (reinterpret_cast<char *>(section.Name) == section_name) {
                return true;
            }
        }

        return false;
    }

    uint32_t PeFile::GetOriginalEntryPoint() {
        return original_entry_point;
    }

    PeArch PeFile::GetPeArch() {
        return type;
    }

    PeArch PeFile::GetPeArch(std::string &path) {
        PeFile patcher(path);
        return patcher.GetPeArch();
    }

    uint32_t PeFile::Align(uint32_t num, uint32_t multiple) {
        return ((num + multiple - 1) / multiple) * multiple;
    }
} // namespace PeEpIntercept
