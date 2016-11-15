#include "ExeManager.h"
#include <stdexcept>
#include <exception>

const DWORD ExeManager::characteristics = 
	IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
	IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

DWORD ExeManager::Align(DWORD num, DWORD multiple) {
	return ((num + multiple - 1) / multiple) * multiple;
}

void ExeManager::PrintError() {
    wchar_t *message_buffer;
    size_t size = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), message_buffer, 256, NULL);

    _tprintf(L"* %s\n", message_buffer);
    LocalFree(message_buffer);
}

ExeManager::ExeManager(wchar_t *target_filepath) {
	executable_handle = CreateFile(target_filepath,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (executable_handle == INVALID_HANDLE_VALUE)
		throw std::runtime_error("CreateFile(): Failed to open file.");

	file_size = GetFileSize(executable_handle, NULL);

	if (file_size == INVALID_FILE_SIZE)
	    throw std::runtime_error("CreateFile(): Failed to get size of file.");

    DWORD bytes_read = 0;
    file_buffer = new char[file_size];

	if (ReadFile(executable_handle, file_buffer, file_size, &bytes_read, NULL) == false)
	    throw std::runtime_error("CreateFile(): Failed to read file.");

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

//TODO: This is not good. Works in release (not debug) mode only. Also unpredictable behavior
size_t ExeManager::CopyProcedure(char *&code_buffer, funptr proc_ptr, funptr proc_end_ptr) {
	size_t addr_entry = (size_t)proc_ptr;
	size_t addr_entry_end = (size_t)proc_end_ptr;

	if (addr_entry >= addr_entry_end)
	    throw std::runtime_error("CopyProcedure(): Procedure pointer is greater or equal than ending procedure pointer.");

	size_t code_buffer_size = addr_entry_end - addr_entry;
	code_buffer = new char[code_buffer_size];
	memcpy(code_buffer, (char*)proc_ptr, code_buffer_size);

	return code_buffer_size;
}

bool ExeManager::AddNewSection(char *new_section_name, DWORD code_size) {
	PIMAGE_SECTION_HEADER last_section = section_headers[file_header->NumberOfSections - 1];
    IMAGE_SECTION_HEADER new_section;

	DWORD section_size_aligned = Align(code_size, optional_header->FileAlignment);
    
    new_section.Characteristics = characteristics;

	new_section.SizeOfRawData = section_size_aligned;

	new_section.Misc.VirtualSize = Align(section_size_aligned,
		optional_header->SectionAlignment);

	new_section.PointerToRawData = Align(last_section->SizeOfRawData + last_section->PointerToRawData, 
		optional_header->FileAlignment);

	new_section.VirtualAddress = Align(last_section->Misc.VirtualSize + last_section->VirtualAddress, 
		optional_header->SectionAlignment);

	memcpy(new_section.Name, new_section_name, IMAGE_SIZEOF_SHORT_NAME);

	// Copy new section to an offset directly after the last section
	DWORD new_section_offset = first_section_offset + (file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	memcpy(&file_buffer[new_section_offset], &new_section, sizeof(IMAGE_SECTION_HEADER));

	// Update the NT headers to accommodate the new section
	file_header->NumberOfSections++;
	optional_header->AddressOfEntryPoint = new_section.VirtualAddress;
	optional_header->SizeOfImage = new_section.VirtualAddress + new_section.Misc.VirtualSize;

	// Update the size of the executable file to accommodate the new section
	DWORD state = SetFilePointer(executable_handle, new_section.PointerToRawData + new_section.SizeOfRawData, NULL, FILE_BEGIN);

    if (state == INVALID_SET_FILE_POINTER)
        throw std::runtime_error("AddNewSection(): Failed to set a file pointer.");

	if(SetEndOfFile(executable_handle) == false)
        throw std::runtime_error("AddNewSection(): Failed to set end-of-file.");
        
	return 0;
}

bool ExeManager::AddNewCodeToSection(int section_index) {
    return false;
}

bool ExeManager::SaveFile(char *code_buffer, DWORD code_buffer_size) {
	DWORD bytes_written = 0;
	DWORD state = SetFilePointer(executable_handle, 0, NULL, FILE_BEGIN);

    if (state == INVALID_SET_FILE_POINTER)
        throw std::runtime_error("SaveFile(): Failed to set a file pointer.");

	if (WriteFile(executable_handle, file_buffer, file_size, &bytes_written, NULL) == false)
        throw std::runtime_error("SaveFile(): Failed to save to file.");

    PIMAGE_SECTION_HEADER last_section = section_headers[file_header->NumberOfSections - 1];
    state = SetFilePointer(executable_handle, last_section->PointerToRawData, NULL, FILE_BEGIN);
    
    // Add new code to new section
    if (state == INVALID_SET_FILE_POINTER)
        throw std::runtime_error("SaveFile(): Failed to set a file pointer for new code.");

	if(WriteFile(executable_handle, code_buffer, code_buffer_size, &bytes_written, NULL))
        throw std::runtime_error("SaveFile(): Failed to save to file for new code.");

	CloseHandle(executable_handle);

	delete[] file_buffer;
	delete[] section_headers;

	return 0;
}

DWORD ExeManager::GetOriginalEntryPoint() {
	return optional_header->AddressOfEntryPoint;
}