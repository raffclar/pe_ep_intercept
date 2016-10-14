#include "ExeManager.h"
#include <stdexcept>
#include <exception>

#define OEP_SIG 0xC1C2C3C4

// These are assembly procedures
extern "C" {
	void Entry();
	void EntryPtr();
}

const DWORD ExeManager::characteristics = 
	IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
	IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

DWORD ExeManager::Align(DWORD num, DWORD multiple) {
    return ((num + multiple - 1) / multiple) * multiple;
}

ExeManager::ExeManager(wchar_t *target_filepath) {
	executable_handle = CreateFile(target_filepath,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (executable_handle == INVALID_HANDLE_VALUE) {
		throw std::runtime_error("CreateFile(): Failed to open file.");
	}

	// Load contents of the file into an array
	DWORD bytes_read = 0;
	file_size = GetFileSize(executable_handle, NULL);
	file_buffer = new char[file_size];
    ReadFile(executable_handle, file_buffer, file_size, &bytes_read, NULL);

	// Portable Executable headers
    dos_header = (PIMAGE_DOS_HEADER)file_buffer;
    nt_header = (PIMAGE_NT_HEADERS)&file_buffer[dos_header->e_lfanew];
    file_header	= (PIMAGE_FILE_HEADER)&nt_header->FileHeader;
    optional_header = (PIMAGE_OPTIONAL_HEADER)&nt_header->OptionalHeader;

    // We need to get the offset for where the NT (file and optional) headers
    // begin and add their size to get the first section offset. 
    first_section_offset = dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS);
    section_headers = new PIMAGE_SECTION_HEADER[file_header->NumberOfSections];
    
    for (int i = 0; i < file_header->NumberOfSections; i++) {
        int next_section_offset = first_section_offset + (i * sizeof(IMAGE_SECTION_HEADER));
        section_headers[i] = (PIMAGE_SECTION_HEADER)(&file_buffer[next_section_offset]);
    }
}

int ExeManager::ModifyFile(char *new_section_name) {
    memset(&new_section, 0, sizeof(IMAGE_SECTION_HEADER));

    PIMAGE_SECTION_HEADER last_section = section_headers[file_header->NumberOfSections - 1];

    //TODO: Get size of new code section from function_buffer
    DWORD dwSectionSize = 200;
    DWORD dwSectionSizeAligned = Align(dwSectionSize, optional_header->FileAlignment);

    new_section.Characteristics = characteristics;
    new_section.SizeOfRawData = dwSectionSizeAligned;

    new_section.Misc.VirtualSize = Align(dwSectionSizeAligned, 
		optional_header->SectionAlignment);

    new_section.PointerToRawData = Align(last_section->SizeOfRawData + last_section->PointerToRawData, 
		optional_header->FileAlignment);

    new_section.VirtualAddress = Align(last_section->Misc.VirtualSize + last_section->VirtualAddress, 
		optional_header->SectionAlignment);

    memcpy(new_section.Name, new_section_name, IMAGE_SIZEOF_SHORT_NAME / 2);

    // Copy new section to an offset directly after the last section
    DWORD new_section_offset = first_section_offset + (file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    memcpy(&file_buffer[new_section_offset], &new_section, sizeof(IMAGE_SECTION_HEADER));

    // Update the NT headers to accommodate the new section
    file_header->NumberOfSections++;
    optional_header->AddressOfEntryPoint = new_section.VirtualAddress;
    optional_header->SizeOfImage = new_section.VirtualAddress + new_section.Misc.VirtualSize;

    // Add new entry code. TODO: This is not good. Works in release (not debug) mode only
    size_t addr_entry = (size_t)Entry;
    size_t addr_entry_ptr = (size_t)EntryPtr;
    function_buffer_size = addr_entry_ptr - addr_entry;
    function_buffer = new char[function_buffer_size];
    memcpy(function_buffer, reinterpret_cast<char*>(&Entry), function_buffer_size);

    // Update the size of the executable file to accommodate the new section
    SetFilePointer(executable_handle, new_section.PointerToRawData + new_section.SizeOfRawData, NULL, FILE_BEGIN);
    SetEndOfFile(executable_handle);

    return 0;
}

int ExeManager::SaveFile() {
    DWORD bytes_written = 0;
    SetFilePointer(executable_handle, 0, NULL, FILE_BEGIN);
    WriteFile(executable_handle, file_buffer, file_size, &bytes_written, NULL);

    SetFilePointer(executable_handle, new_section.PointerToRawData, NULL, FILE_BEGIN);
    WriteFile(executable_handle, function_buffer, function_buffer_size, &bytes_written, NULL);

    CloseHandle(executable_handle);

    delete[] file_buffer;
    delete[] section_headers;
    delete[] function_buffer;

    return 0;
}