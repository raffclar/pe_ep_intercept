#include <cstring>
#include "PePatchX64.hpp"
#include "Assembly.hpp"
#include "PeStructs.hpp"

namespace Interceptor {
    std::vector<char> PePatchX64::patch() {
        //addSection(".3lc");
        return file.getFileContents();
    };

    void PePatchX64::addSection(const std::string &name) {
        auto optional_header = file.getOptionalHeaderX64();
        auto section_headers = file.getSectionHeaders();
        auto file_header = file.getCoffHeader();
        auto last_section = section_headers.back();

        // Assemble code with oep
        uint32_t ep = file.getEntryPoint();
        std::vector<char> code = assembler.assemble(MachineType::x64, entryRedirectAssemblyX64(ep));
        auto code_size = static_cast<uint32_t>(code.size());

        auto aligned_size = Align(code_size, optional_header.file_alignment);

        SectionHeader new_section = {};
        new_section.Misc.virtual_size = Align(aligned_size, optional_header.section_alignment),
        new_section.virtual_address = Align(
                last_section.Misc.virtual_size + last_section.virtual_address,
                optional_header.section_alignment
        ),
        new_section.size_of_raw_data = aligned_size,
        new_section.pointer_to_raw_data = Align(
                last_section.size_of_raw_data + last_section.pointer_to_raw_data,
                optional_header.file_alignment
        ),
        new_section.pointer_to_relocations  = 0,
        new_section.pointer_to_line_numbers = 0,
        new_section.number_of_relocations   = 0,
        new_section.pointer_to_line_numbers = 0,
        new_section.characteristics         = section_rights;

        for (size_t i = 0; i < section_name_size; i++) {
            char letter;

            if (i < name.length()) {
                letter = name.at(i);
            } else {
                letter = '\0';
            }

            new_section.name[i] = static_cast<uint8_t>(letter);
        }

        // Padding is be required otherwise the loader will fail
        // when loading the executable
        while (code.size() < new_section.size_of_raw_data) {
            code.push_back(0);
        }

        file.appendFileData(code);

        file.addSectionHeader(new_section);
        file_header.number_of_sections++;
        file.setFileHeader(file_header);

        // The oep is replaced with one pointing to the new code
        // optional_header.AddressOfEntryPoint = new_section.VirtualAddress;
        optional_header.size_of_image = new_section.virtual_address + new_section.Misc.virtual_size;
        file.setOptionalHeaderX64(optional_header);
    }
}
