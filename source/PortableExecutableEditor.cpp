#include "PortableExecutableEditor.h"
#include <stdexcept>
#include <exception>

#define OEP_SIG 0xC1C2C3C4

const DWORD PortableExecutableEditor::characteristics = 
	IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
    IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

DWORD PortableExecutableEditor::Align(DWORD num, DWORD multiple) {
    return ((num + multiple - 1) / multiple) * multiple;
}

// Declaring as static will compile function in sequence to the next static function
// Note: this is not at all safe or expected
__declspec(noinline) static int NewMain() {
	unsigned long address;
	unsigned long base_address;
	LDR_MODULE *module;

	// Get current address and pointer to Process Environment Block (PEB)
	__asm {
		call L1
		L1 : pop address
				mov eax, dword ptr fs : [0x30]
				mov module, eax
	}

	module = (LDR_MODULE *)((PEB *)module)->LoaderData->InLoadOrderModuleList.Flink;
	while (module->BaseAddress) {
		unsigned long base = (unsigned long)module->BaseAddress;
		unsigned long difference = address - base;

		if (base + difference == address) {
			base_address = base;
			break;
		}

		module = (LDR_MODULE *)module->InLoadOrderModuleList.Flink;
	}

	// Jump to the original entry point
	__asm {
		mov edx, base_address
		mov eax, OEP_SIG // Original entry point will be stored here
		or edx, eax
		jmp edx
	}
}

// Empty function that exists purely to act as a pointer to memory
__declspec(noinline) static void NewMainEnd() {
    return;
}

PortableExecutableEditor::PortableExecutableEditor(wchar_t *target_filepath) {
	executable_handle = CreateFile(target_filepath,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (executable_handle == INVALID_HANDLE_VALUE) {
		throw std::runtime_error("CreateFile(): Failed to open file.");
	}

    file_size = GetFileSize(executable_handle, NULL);
    file_buffer = new char[file_size];

    DWORD bytes_read = 0;
    ReadFile(executable_handle, file_buffer, file_size, &bytes_read, NULL);

    dos_header = (PIMAGE_DOS_HEADER)file_buffer;
    nt_header = (PIMAGE_NT_HEADERS)&file_buffer[dos_header->e_lfanew];
    file_header = (PIMAGE_FILE_HEADER)&nt_header->FileHeader;
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

int PortableExecutableEditor::ModifyFile(char *new_section_name) {
    memset(&new_section, 0, sizeof(IMAGE_SECTION_HEADER));

    PIMAGE_SECTION_HEADER last_section = section_headers[file_header->NumberOfSections - 1];

    //TODO: Get size of new code section from function_buffer
    DWORD dwSectionSize = 200;
    DWORD dwSectionSizeAligned = Align(dwSectionSize, optional_header->FileAlignment);

    new_section.Characteristics = characteristics;
    new_section.SizeOfRawData = dwSectionSizeAligned;
    new_section.Misc.VirtualSize = Align(dwSectionSizeAligned, optional_header->SectionAlignment);
    new_section.PointerToRawData = Align(last_section->SizeOfRawData + last_section->PointerToRawData, optional_header->FileAlignment);
    new_section.VirtualAddress = Align(last_section->Misc.VirtualSize + last_section->VirtualAddress, optional_header->SectionAlignment);
    memcpy(new_section.Name, new_section_name, IMAGE_SIZEOF_SHORT_NAME / 2);

    // Copy new section to an offset directly after the last section
    DWORD new_section_offset = first_section_offset + (file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    memcpy(&file_buffer[new_section_offset], &new_section, sizeof(IMAGE_SECTION_HEADER));

    // Update the NT headers to accommodate the new section
    file_header->NumberOfSections++;
    optional_header->AddressOfEntryPoint = new_section.VirtualAddress;
    optional_header->SizeOfImage = new_section.VirtualAddress + new_section.Misc.VirtualSize;

    // Add new entry code. TODO: This is not good
    size_t pointer_NewMain = (size_t)NewMain;
    size_t pointer_NewMainEnd = (size_t)NewMainEnd;
    function_buffer_size = pointer_NewMainEnd - pointer_NewMain;
    function_buffer = new char[function_buffer_size];
    memcpy(function_buffer, reinterpret_cast<char*>(&NewMain), function_buffer_size);

    // Update the size of the executable file to accommodate the new section
    SetFilePointer(executable_handle, new_section.PointerToRawData + new_section.SizeOfRawData, NULL, FILE_BEGIN);
    SetEndOfFile(executable_handle);

    return 0;
}

int PortableExecutableEditor::SaveFile() {
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