#include <cstring>
#include "PePatchX64.hpp"
#include "PeStructs.hpp"

namespace Interceptor {
    PeFile PePatchX64::patch(const std::string &section) {
        addSection(section);
        return file;
    };

    void PePatchX64::addSection(const std::string &name) {
        auto optional_header = file.getOptionalHeaderX64();
        auto section_headers = file.getSectionHeaders();
        auto file_header = file.getFileHeader();
        auto last_section = section_headers.back();

        // Assemble code with original entry point
        auto oep = file.getEntryPoint();
        auto code = assembler.assemble(Architecture::x64, entryRedirectAssemblyX64(oep));
        auto code_size = static_cast<uint32_t>(code.size());
        auto aligned_size = align(code_size, optional_header.FileAlignment);

        RawHeaders::SectionHeader new_section = {};
        new_section.misc.virtual_size = align(aligned_size, optional_header.section_alignment),
        new_section.virtual_address = align(
                last_section.misc.virtual_size + last_section.virtual_address,
                optional_header.section_alignment
        ),
        new_section.size_of_raw_data = aligned_size,
        new_section.pointer_to_raw_data = align(
                last_section.size_of_raw_data + last_section.pointer_to_raw_data,
                optional_header.FileAlignment
        ),
        new_section.pointer_to_relocations = 0,
        new_section.pointer_to_line_numbers = 0,
        new_section.number_of_relocations = 0,
        new_section.number_of_line_numbers = 0,
        new_section.characteristics  = section_rights;

        for (size_t i = 0; i < RawHeaders::section_name_size; i++) {
            char letter;

            if (i < name.length()) {
                letter = name.at(i);
            } else {
                letter = '\0';
            }

            new_section.name[i] = static_cast<uint8_t>(letter);
        }

        file.addSectionHeader(new_section);
        file_header.number_of_sections++;
        file.setFileHeader(file_header);

        // Padding is be required otherwise the loader will fail
        // when loading the executable
        while (code.size() < new_section.size_of_raw_data) {
            code.push_back(0);
        }

        file.appendFileData(code);

        // The oep is replaced with one pointing to the new code
        optional_header.AddressOfEntryPoint = new_section.virtual_address;
        optional_header.SizeOfImage = new_section.virtual_address + new_section.misc.virtual_size;
        file.setOptionalHeaderX64(optional_header);
    }
}
