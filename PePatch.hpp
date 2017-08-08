#include <string>
#include <memory>
#include <vector>
#include <fstream>

#include "windows.h"
#include <imagehlp.h>

// http://www.ntinternals.net
// Tomasz Nowak, 2000-2015.
#include "ntundoc.h"

class PePatch {
private:
    std::string path;
	std::fstream file_input;
	std::vector<char> file_buffer;

    uint32_t nt_header_signature;
    IMAGE_DOS_HEADER dos_header;
    IMAGE_FILE_HEADER file_header;
    IMAGE_OPTIONAL_HEADER optional_header;
	std::vector<IMAGE_SECTION_HEADER> section_headers;

    static uint32_t Align(uint32_t number, uint32_t multiple);
    static bool ReplaceDword(std::vector<char> code_buffer, uint32_t target_value, uint32_t replacement_value);
    static std::vector<char> CopyBytes(char *byte_start, char *byte_end);
public:
    explicit PePatch(std::string path);
	std::string CreateEntryPointSubroutine(uint32_t original_entry_point);
    std::vector<char> Assemble(const std::string &assembly);
    void AddSection(const std::string &new_section_name, uint32_t code_size);
    void SaveFile(std::string new_path, std::vector<char> subroutine_buffer);
};