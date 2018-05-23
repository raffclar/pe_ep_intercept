#include "PeFile.hpp"
#include <cinttypes>
#include <iostream>

namespace Interceptor {

    PeFile::PeFile(std::fstream &file_stream) {
        std::streamsize size = file_stream.tellg();
        file_stream.seekg(0, std::ios::beg);

        if (size <= 0) {
            throw std::runtime_error("Could not get file size");
        }

        std::vector<char> file_contents(static_cast<unsigned long>(size));

        if (!file_stream.read(file_contents.data(), size)) {
            throw std::runtime_error("Could not read file");
        }

        const auto *raw_buffer = file_contents.data();

        dos_header = *(RawHeaders::DosHeader*) raw_buffer;

        uint16_t e_magic_short = ((uint16_t)dos_header.e_magic[1]) << 8;
        e_magic_short = e_magic_short | dos_header.e_magic[0];

        if (e_magic_short != RawHeaders::dos_signature) {
            throw std::runtime_error("DOS header signature is corrupt.");
        }

        size_t machine_offset = dos_header.e_lfanew + sizeof(uint32_t);
        auto machine = static_cast<uint16_t>((raw_buffer[machine_offset + 1] << 8) + raw_buffer[machine_offset]);

        switch (machine) {
            case 0x014c:
                type = Architecture::x86;
                break;
            case 0x8664:
                type = Architecture::x64;
                break;
            default:
                throw std::runtime_error("COFF header machine type is unknown");
        }

        nt_header_signature = 0;
        entry_point = 0;
        coff_header = {};

        uint32_t first_section = 0;

        if (type == Architecture::x64) {
            auto nt_header = *(RawHeaders::NtHeaderX64*) &raw_buffer[dos_header.e_lfanew];
            coff_header = nt_header.coff;
            first_section = dos_header.e_lfanew + sizeof(nt_header);
            nt_header_signature = nt_header.signature;
            optional_header_x64 = nt_header.optional;
            entry_point = optional_header_x64.AddressOfEntryPoint;
        } else {
            auto nt_header = *(RawHeaders::NtHeaderX86*) &raw_buffer[dos_header.e_lfanew];
            coff_header = nt_header.coff;
            first_section = dos_header.e_lfanew + sizeof(nt_header);
            nt_header_signature = nt_header.signature;
            optional_header_x86 = nt_header.optional;
            entry_point = optional_header_x86.AddressOfEntryPoint;
        }

        if (nt_header_signature != RawHeaders::nt_signature) {
            throw std::runtime_error("NT header signature is corrupt");
        }

        for (int i = 0; i < coff_header.number_of_sections; i++) {
            uint32_t section_index = i * sizeof(RawHeaders::SectionHeader);
            uint32_t next_section = first_section + section_index;
            auto hdr = *(RawHeaders::SectionHeader*) &raw_buffer[next_section];
            section_headers.push_back(hdr);
        }

        auto last_section = section_headers.back();
        auto pe_size = last_section.pointer_to_raw_data + last_section.size_of_raw_data;
        // Outside the PE image
        auto data_start = file_contents.begin() + pe_size;
        auto headers_size = first_section;
        auto count = static_cast<uint32_t>(section_headers.size());
        headers_size += count * sizeof(RawHeaders::SectionHeader);
        // Start of PE sections
        auto section_data_start = file_contents.begin() + headers_size;

        section_data.assign(section_data_start, data_start);
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

    Architecture PeFile::getPeArch() {
        return type;
    }

    RawHeaders::CoffHeader PeFile::getFileHeader() {
        return coff_header;
    }

    RawHeaders::OptionalHeaderX64 PeFile::getOptionalHeaderX64() {
        return optional_header_x64;
    }

    RawHeaders::OptionalHeaderX86 PeFile::getOptionalHeaderX86() {
        return optional_header_x86;
    }

    std::vector<RawHeaders::SectionHeader> PeFile::getSectionHeaders() {
        return section_headers;
    }

    uint32_t PeFile::getEntryPoint(){
        return entry_point;
    }

    void PeFile::addSectionHeader(RawHeaders::SectionHeader header) {
        section_headers.push_back(header);
    }

    void PeFile::setFileHeader(RawHeaders::CoffHeader file_header) {
        this->coff_header = file_header;
    }

    void PeFile::setOptionalHeaderX64(RawHeaders::OptionalHeaderX64 optional_header) {
        this->optional_header_x64 = optional_header;
    }

    void PeFile::setOptionalHeaderX86(RawHeaders::OptionalHeaderX86 optional_header) {
        this->optional_header_x86 = optional_header;
    }

    void PeFile::appendFileData(std::vector<char> new_data) {
        file_data.insert(file_data.end(), new_data.begin(), new_data.end());
    }

    void PeFile::write(std::fstream &file) {
        RawHeaders::DosHeader dos = this->dos_header;
        RawHeaders::CoffHeader coff_header = this->coff_header;
        RawHeaders::OptionalHeaderX64 optional_header = this->optional_header_x64;

        auto binwrite = [&file](auto val) mutable {
            file.write(reinterpret_cast<const char*>(val), sizeof(*val));
        };

        // Write each individual struct member to avoid writing packing bytes
        binwrite(&dos.e_magic);
        binwrite(&dos.e_cblp);
        binwrite(&dos.e_cp);
        binwrite(&dos.e_crlc);
        binwrite(&dos.e_cparhdr);
        binwrite(&dos.e_minalloc);
        binwrite(&dos.e_maxalloc);
        binwrite(&dos.e_ss);
        binwrite(&dos.e_sp);
        binwrite(&dos.e_csum);
        binwrite(&dos.e_ip);
        binwrite(&dos.e_cs);
        binwrite(&dos.e_lfarlc);
        binwrite(&dos.e_ovno);
        binwrite(&dos.e_res);
        binwrite(&dos.e_oemid);
        binwrite(&dos.e_oeminfo);
        binwrite(&dos.e_res2);
        binwrite(&dos.e_lfanew);

        binwrite(&this->nt_header_signature);

        binwrite(&coff_header.machine);
        binwrite(&coff_header.number_of_sections);
        binwrite(&coff_header.time_datestamp);
        binwrite(&coff_header.pointer_to_symbol_table);
        binwrite(&coff_header.number_of_symbols);
        binwrite(&coff_header.size_of_optional_header);
        binwrite(&coff_header.characteristics);

        binwrite(&optional_header.Magic);
        binwrite(&optional_header.MajorLinkerVersion);
        binwrite(&optional_header.MinorLinkerVersion);
        binwrite(&optional_header.SizeOfCode);
        binwrite(&optional_header.SizeOfInitializedData);
        binwrite(&optional_header.SizeOfUninitializedData);
        binwrite(&optional_header.AddressOfEntryPoint);
        binwrite(&optional_header.BaseOfCode);
        binwrite(&optional_header.ImageBase);
        binwrite(&optional_header.section_alignment);
        binwrite(&optional_header.FileAlignment);
        binwrite(&optional_header.MajorOperatingSystemVersion);
        binwrite(&optional_header.MinorOperatingSystemVersion);
        binwrite(&optional_header.MajorImageVersion);
        binwrite(&optional_header.MinorImageVersion);
        binwrite(&optional_header.MajorSubsystemVersion);
        binwrite(&optional_header.MinorSubsystemVersion);
        binwrite(&optional_header.Win32VersionValue);
        binwrite(&optional_header.SizeOfImage);
        binwrite(&optional_header.SizeOfHeaders);
        binwrite(&optional_header.CheckSum);
        binwrite(&optional_header.Subsystem);
        binwrite(&optional_header.DllCharacteristics);
        binwrite(&optional_header.SizeOfStackReserve);
        binwrite(&optional_header.SizeOfStackCommit);
        binwrite(&optional_header.SizeOfHeapReserve);
        binwrite(&optional_header.SizeOfHeapCommit);
        binwrite(&optional_header.LoaderFlags);
        binwrite(&optional_header.NumberOfRvaAndSizes);
        binwrite(&optional_header.dataDirectory);

        for (auto section_header : section_headers) {
            std::cout << "Writing header: \"" << section_header.name << "\"." << std::endl;
            binwrite(&section_header.name);
            binwrite(&section_header.misc.virtual_size);
            binwrite(&section_header.virtual_address);
            binwrite(&section_header.size_of_raw_data);
            binwrite(&section_header.pointer_to_raw_data);
            binwrite(&section_header.pointer_to_relocations);
            binwrite(&section_header.pointer_to_line_numbers);
            binwrite(&section_header.number_of_relocations);
            binwrite(&section_header.number_of_line_numbers);
            binwrite(&section_header.characteristics);
        }

        std::cout << "Writing section data." << std::endl;
        file.write(section_data.data(), section_data.size());

        std::cout << "Writing rest of data." << std::endl;
        file.write(file_data.data(), file_data.size());
    }
} // namespace Interceptor
