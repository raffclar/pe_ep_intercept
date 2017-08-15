#include "PePatch.hpp"
#include <keystone/keystone.h>
#include <cinttypes>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <memory>

static const uint32_t SECTION_CHARACTERISTICS =
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

static bool ReplaceDword(std::vector<char> code_buffer, uint32_t target_dword, uint32_t replace_dword) {
    for (size_t i = 0; i < code_buffer.size(); i++) {
        // First byte
        if (code_buffer[i] != (target_dword & 0xff)) {
            continue;
        }

        size_t j = 1;

        while (j < 4) {
            // Rest of bytes
            if (code_buffer[i + j] == (target_dword >> ((8 * j) & 0xff))) {
                j++;
            } else {
                // Failed to match all bytes
                break;
            }
        }

        if (j == 4) {
            for (size_t re_i = 0; re_i < j; re_i++) {
                uint32_t num = (replace_dword >> (8 * re_i)) & 0xff;
                auto replace_byte = static_cast<char>(num);
                code_buffer[i + re_i] = replace_byte;
            }

            return true;
        }
    }

    return false;
}

namespace PeEpIntercept {
    PePatch::PePatch(std::string path) {
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

    std::vector<char> PePatch::Assemble(const std::string &assembly) {
        std::vector<char> instructions;

        if (assembly.empty()) {
            return instructions;
        }

        unsigned char *encode = nullptr;
        ks_engine *ks = nullptr;
        size_t count;
        size_t size;

        auto code_deleter = [](unsigned char *code_ptr) {
            ks_free(code_ptr);
        };

        auto ks_deleter = [](ks_engine *ks_ptr) {
            ks_close(ks_ptr);
        };

        ks_mode instruct_mode;

        switch (type) {
            case PeArch::x86:
                instruct_mode = KS_MODE_32;
                break;
            case PeArch::x64:
                instruct_mode = KS_MODE_64;
                break;
            default:
                throw std::runtime_error("executable type not supported");
        }

        if (ks_open(KS_ARCH_X86, instruct_mode, &ks) != KS_ERR_OK) {
            throw std::runtime_error("failed to open keystone");
        }

        std::unique_ptr<ks_engine[],
                decltype(ks_deleter)> ks_ptr(ks, ks_deleter);

        if (ks_asm(ks, assembly.c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
            throw std::runtime_error("failed to assemble instructions");
        }

        std::unique_ptr<unsigned char[],
                decltype(code_deleter)> encode_ptr(encode, code_deleter);

        if (size > 0xffffffff) {
            throw std::runtime_error("exceeded max section size");
        }

        for (size_t i = 0; i < size; i++) {
            auto encoded = static_cast<char>(encode[i]);
            instructions.push_back(encoded);
        }

        return instructions;
    }

    bool PePatch::HasSection(const std::string &section_name) {
        for (auto &section : section_headers) {
            if (reinterpret_cast<char *>(section.Name) == section_name) {
                return true;
            }
        }

        return false;
    }

    uint32_t PePatch::GetOriginalEntryPoint() {
        return original_entry_point;
    }

    PeArch PePatch::GetPeArch() {
        return type;
    }

    PeArch PePatch::GetPeArch(std::string &path) {
        PePatch patcher(path);
        return patcher.GetPeArch();
    }

    uint32_t PePatch::Align(uint32_t num, uint32_t multiple) {
        return ((num + multiple - 1) / multiple) * multiple;
    }
} // namespace PeEpIntercept
