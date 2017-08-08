#include <iostream>
#include <keystone/keystone.h>
#include <cinttypes>
#include "PePatch.hpp"

const static uint32_t SECTION_MAX_NAME_SIZE = IMAGE_SIZEOF_SHORT_NAME;

const static uint32_t SECTION_CHARACTERISTICS =
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

uint32_t PePatch::Align(uint32_t num, uint32_t multiple) {
    return ((num + multiple - 1) / multiple) * multiple;
}

bool PePatch::ReplaceDword(std::vector<char> code_buffer, uint32_t target_value, uint32_t replacement_value) {
    for (size_t i = 0; i < code_buffer.size(); i++) {
        if (code_buffer[i] != (target_value & 0xFF)) { // First byte
            continue;
        }

        size_t j = 1;

        while (j < 4) {
            if (code_buffer[i + j] == (target_value >> ((8 * j) & 0xFF))) { // Rest of bytes
                j++;
            } else {
                break; // Failed to match all bytes
            }
        }

        if (j == 4) {
            for (size_t re_i = 0; re_i < j; re_i++) {
                auto replace_byte = static_cast<char>((replacement_value >> (8 * re_i)) & 0xFF);
                code_buffer[i + re_i] = replace_byte;
            }

            return true;
        }
    }

    return false;
}

static std::vector<char> PePatch::CopyBytes(char *byte_start, char *byte_end) {
    if (byte_start >= byte_end) {
        throw std::runtime_error("pointer is greater or equal than ending pointer");
    }

    std::vector<char> subroutine_buffer(byte_start, byte_end);
    return subroutine_buffer;
}

PePatch::PePatch(std::string path) : path(path) {
    file_input.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    file_input.open(path, std::ios::binary | std::ifstream::ate | std::fstream::in | std::fstream::out);
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

    // Portable Executable headers
    dos_header = *(PIMAGE_DOS_HEADER) raw_buffer;
    auto nt_header = (PIMAGE_NT_HEADERS) &raw_buffer[dos_header.e_lfanew];
    file_header = *(PIMAGE_FILE_HEADER) &nt_header->FileHeader;
    optional_header = *(PIMAGE_OPTIONAL_HEADER) &nt_header->OptionalHeader;
    nt_header_signature = nt_header->Signature;
    uint32_t first_section_offset = dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS);

    for (uint32_t i = 0; i < file_header.NumberOfSections; i++) {
        uint32_t next_section_offset = first_section_offset + (i * sizeof(IMAGE_SECTION_HEADER));
        auto hdr = *(PIMAGE_SECTION_HEADER) &raw_buffer[next_section_offset];
        section_headers.push_back(hdr);
    }
}

std::string PePatch::CreateEntryPointSubroutine(uint32_t original_entry_point) {
    std::string address;
    address.resize(9);
    snprintf(&address[0], 9, "%08" PRIx32, original_entry_point);

    return "LEA RAX, [RIP];";
}

std::vector<char> PePatch::Assemble(const std::string &assembly) {
    std::vector<char> instructions;
    unsigned char *encode;
    ks_engine *ks;
    size_t count;
    size_t size;

    if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK) {
        throw std::runtime_error("failed to open keystone");
    }

    if (ks_asm(ks, assembly.c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
        throw std::runtime_error("failed to assemble instructions");
    }

    for (size_t i = 0; i < size; i++) {
        instructions.push_back(static_cast<char>(encode[i]));
    }

    ks_free(encode);
    ks_close(ks);

    return instructions;

}

void PePatch::AddSection(const std::string &new_section_name, uint32_t code_size) {
    auto last_section = section_headers.back();
    auto aligned_size = Align(code_size, optional_header.FileAlignment);
    IMAGE_SECTION_HEADER new_section{};

    new_section.Characteristics = SECTION_CHARACTERISTICS;
    new_section.SizeOfRawData = aligned_size;
    new_section.Misc.VirtualSize = Align(aligned_size, optional_header.SectionAlignment);
    new_section.PointerToRawData = Align(last_section.SizeOfRawData + last_section.PointerToRawData,
                                         optional_header.FileAlignment);
    new_section.VirtualAddress = Align(last_section.Misc.VirtualSize + last_section.VirtualAddress,
                                       optional_header.SectionAlignment);

    for (size_t i = 0; i < SECTION_MAX_NAME_SIZE; i++) {
        char letter;

        if (i < new_section_name.length()) {
            letter = new_section_name.at(i);
        } else {
            letter = '\0';
        }

        new_section.Name[i] = static_cast<uint8_t>(letter);
    }

    file_header.NumberOfSections++;
    optional_header.AddressOfEntryPoint = new_section.VirtualAddress;
    optional_header.SizeOfImage = new_section.VirtualAddress + new_section.Misc.VirtualSize;
    section_headers.push_back(new_section);
}

void PePatch::SaveFile(std::string new_path, std::vector<char> subroutine_buffer) {
    char dos_bytes[sizeof(dos_header)];
    memcpy(dos_bytes, &dos_header, sizeof(dos_header));
    file_input.seekg(0);
    file_input.write(dos_bytes, sizeof(dos_header));

    //
    IMAGE_NT_HEADERS nt_headers{nt_header_signature, file_header, optional_header};

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
    uint32_t new_section_offset = new_section->PointerToRawData;
    file_input.seekg(new_section_offset);

    // Padding is required otherwise the loader will fail the executable
    while(subroutine_buffer.size() < new_section->SizeOfRawData) {
        subroutine_buffer.push_back(0);
    }

    file_input.write(subroutine_buffer.data(), subroutine_buffer.size());
}
