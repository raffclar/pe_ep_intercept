#include <cstring>
#include "PePatchX64.hpp"
#include "Assembly.hpp"
#include "PeStructs.hpp"

namespace Interceptor {
    std::vector<char> PePatchX64::patch() {
        addSection(".3lc");
        return file.getFileContents();
    };

    void PePatchX64::addSection(const std::string &name) {
        auto optional_header = file.getOptionalHeaderX64();
        auto section_headers = file.getSectionHeaders();
        auto file_header = file.getFileHeader();
        auto last_section = section_headers.back();

        // Assemble code with oep
        uint32_t ep = file.getEntryPoint();
        std::vector<char> code = assembler.assemble(PeArch::x64, entryRedirectAssemblyX64(ep));
        auto code_size = static_cast<uint32_t>(code.size());

        auto aligned_size = Align(code_size, optional_header.FileAlignment);

        SectionHeader new_section = {};
        new_section.Misc.VirtualSize = Align(aligned_size, optional_header.SectionAlignment),
        new_section.VirtualAddress = Align(
                last_section.Misc.VirtualSize + last_section.VirtualAddress,
                optional_header.SectionAlignment
        ),
        new_section.SizeOfRawData = aligned_size,
        new_section.PointerToRawData = Align(
                last_section.SizeOfRawData + last_section.PointerToRawData,
                optional_header.FileAlignment
        ),
        new_section.PointerToRelocations = 0,
        new_section.PointerToLinenumbers = 0,
        new_section.NumberOfRelocations = 0,
        new_section.NumberOfLinenumbers = 0,
        new_section.Characteristics  = section_rights;

        for (size_t i = 0; i < section_name_size; i++) {
            char letter;

            if (i < name.length()) {
                letter = name.at(i);
            } else {
                letter = '\0';
            }

            new_section.Name[i] = static_cast<uint8_t>(letter);
        }

        // Padding is be required otherwise the loader will fail
        // when loading the executable
        while (code.size() < new_section.SizeOfRawData) {
            code.push_back(0);
        }

        file.appendFileData(code);

        file.addSectionHeader(new_section);
        file_header.NumberOfSections++;
        file.setFileHeader(file_header);

        // The oep is replaced with one pointing to the new code
        optional_header.AddressOfEntryPoint = new_section.VirtualAddress;
        optional_header.SizeOfImage = new_section.VirtualAddress + new_section.Misc.VirtualSize;
        file.setOptionalHeaderX64(optional_header);
    }
}
