#include "PeFile.hpp"
#include "PeStructs.hpp"
#include <cinttypes>
#include <iostream>

namespace Interceptor {
    PeFile::PeFile(std::vector<char> file_contents) : file_data(file_contents) {
        const auto *raw_buffer = file_contents.data();

		// Retrieve DOS header
        dos_header = *(DosHeader*) raw_buffer;

        if (dos_header.e_magic[0] != 'M' || dos_header.e_magic[1] != 'Z') {
            throw std::runtime_error("the DOS signature is invalid");
        }

		// Retrieve the DOS stub
		for (int i = sizeof(dos_header); i < dos_header.e_lfanew; i++) {
			dos_stub.push_back(raw_buffer[i]);
		}

		// Peak ahead in the COFF header to check what machine type this executable image was compiled for
        size_t machine_offset = dos_header.e_lfanew + sizeof(nt_header_signature);
        auto machine = static_cast<uint16_t>((raw_buffer[machine_offset + 1] << 8) + raw_buffer[machine_offset]);

        switch (machine) {
            case 0x014c:
                type = MachineType::x86;
                break;
            case 0x8664:
                type = MachineType::x64;
                break;
            default:
                throw std::runtime_error("executable type is not x86 or x64");
        }

		// COFF header and NT optional header
        uint32_t first_section_address = 0;

        if (type == MachineType::x64) {
            auto nt_header        = *(NtHeaderX64*) &raw_buffer[dos_header.e_lfanew];
            file_header           = *(CoffHeader*) &nt_header.coff;
            first_section_address = dos_header.e_lfanew + sizeof(nt_header);
            optional_header_x64   = *(OptionalHeaderX64*) &nt_header.optional;
            entry_point           = optional_header_x64.address_of_entry_point;
			nt_header_signature   = nt_header.signature;
        } else {
            auto nt_header        = *(NtHeaderX86*) &raw_buffer[dos_header.e_lfanew];
            file_header           = *(CoffHeader*) &nt_header.coff;
            first_section_address = dos_header.e_lfanew + sizeof(nt_header);
            optional_header_x86   = *(OptionalHeaderX86*) &nt_header.optional;
            entry_point           = optional_header_x86.address_of_entry_point;
			nt_header_signature   = nt_header.signature;
        }

        if (nt_header_signature != 0x4550) {
            throw std::runtime_error("the NT signature is invalid");
        }

        for (int i = 0; i < file_header.number_of_sections; i++) {
            uint32_t next_section   = first_section_address + i * sizeof(SectionHeader);
            auto section_header     = *(SectionHeader*) &raw_buffer[next_section];
            section_headers.push_back(section_header);
        }

        auto section_header_count = static_cast<uint32_t>(section_headers.size());
        auto image_size = first_section_address + (section_header_count * sizeof(SectionHeader));

        // Excludes headers since we already have the initialised structs
        auto data_start = file_contents.begin() + image_size;
        file_data.assign(data_start, file_contents.end());
    }

    bool PeFile::hasSection(const std::string &section_name) {
        for (auto &section : section_headers) {
            if (reinterpret_cast<char *>(section.name) == section_name) {
                return true;
            }
        }

        return false;
    }

	DosHeader PeFile::getDosHeader() {
		return dos_header;
	}

    MachineType PeFile::getMachineType() {
        return type;
    }

    CoffHeader PeFile::getCoffHeader() {
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
		auto *dos_header_bytes = (char*)(&dos_header);
		auto length = sizeof(dos_header);
		file_contents.insert(file_contents.end(), dos_header_bytes, dos_header_bytes + length);

		// DOS stub
		file_contents.insert(std::end(file_contents), std::begin(dos_stub), std::end(dos_stub));

		// NT header
        NtHeaderX64 nt_header {
                nt_header_signature,
                file_header,
                optional_header_x64
        };

        auto *nt_header_bytes = (char*)(&nt_header);
        length = sizeof(nt_header);
        file_contents.insert(file_contents.end(), nt_header_bytes, nt_header_bytes + length);

        // Section headers
        uint32_t section_offset = dos_header.e_lfanew + sizeof(nt_header);

        for (auto &section_header : section_headers) {
            auto section_header_bytes = (char*)(&section_header);
            length = sizeof(section_header);
            file_contents.insert(file_contents.end(), section_header_bytes, section_header_bytes + length);
            section_offset += sizeof(section_header);
        }

        // Rest of executable
        auto new_section = &section_headers.back();
        uint32_t code_start = new_section->pointer_to_raw_data;
        file_contents.insert(file_contents.end(), file_data.begin(), file_data.end());

        return file_contents;
    }
} // namespace Interceptor
