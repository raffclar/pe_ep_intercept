#pragma once
#pragma warning(disable: 4091) // Fix for imagehlp.h typedef issues
#pragma comment(lib , "Imagehlp.lib")

#include <windows.h>
#include <tchar.h>
#include <imagehlp.h>

// http://www.ntinternals.net
// Tomasz Nowak, 2000-2015.
#include "ntundoc.h"

typedef void(*funptr);

class ExeManager {
private:
    HANDLE executable_handle;

    // Common object file format flags
    const static DWORD characteristics;

    DWORD file_size;
    DWORD first_section_offset;
    char *file_buffer;
    char *function_buffer;

    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS nt_header;
    PIMAGE_FILE_HEADER file_header;
    PIMAGE_OPTIONAL_HEADER optional_header;
    PIMAGE_SECTION_HEADER *section_headers;
    IMAGE_SECTION_HEADER new_section;

    size_t function_buffer_size;

    static DWORD Align(DWORD number, DWORD multiple);
public:
    ExeManager(wchar_t *target_filepath);
	int CopyProcedure(char *function_buffer, funptr ProcPtr, funptr ProcEndPtr);
    int ModifyFile(char *pszSectionName);
    int SaveFile();
};