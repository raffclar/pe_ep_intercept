#include <iostream>
#include <string>
#include <vector>
#include <limits>

#define _CRT_SECURE_NO_WARNINGS

#include "PortableExecutableEditor.h"

// https://github.com/brofield/simpleopt
// MIT license
#include "utils/SimpleOpt.h"

enum { OPT_HELP, OPT_PATH, OPT_SECT};

CSimpleOpt::SOption g_rgOptions[] = {
    { OPT_PATH, L"-p",        SO_REQ_SEP },
    { OPT_SECT, L"-s",        SO_REQ_SEP },
    { OPT_SECT, L"--section", SO_REQ_SEP },
    { OPT_HELP, L"-h",        SO_NONE },
    { OPT_HELP, L"--help",    SO_NONE },
    SO_END_OF_OPTIONS
};

void printUsage() {
    wprintf(L"Usage: PortableExecutablePatcher.exe "
             "[-p PATH] [-s SECTION_NAME] " 
             "[--section SECTION_NAME] [-h] [--help]\n");
}

int _tmain(int argc, wchar_t *argv[]) {
    if (argc <= 1) {
        printUsage();
        return 0;
    }

    CSimpleOpt args(argc, argv, g_rgOptions, SO_O_EXACT);

	const size_t name_size = IMAGE_SIZEOF_SHORT_NAME / 2;
    char target_section_name[name_size];
	size_t name_bytes_copied = 0;

	wchar_t *target_filepath;
    _ESOError eso_state = SO_SUCCESS;

    while (args.Next() && eso_state == SO_SUCCESS) {
        eso_state = args.LastError();
        if (eso_state == SO_SUCCESS) {
            switch (args.OptionId()) {
            case OPT_HELP:
                printUsage();
                return 0;
            case OPT_PATH:
                target_filepath = args.OptionArg();
                break;
            case OPT_SECT:
                wcstombs_s(&name_bytes_copied, target_section_name, name_size, args.OptionArg(), name_size);
                break;
            }
        } else if (eso_state == SO_OPT_INVALID) {
            _tprintf(L"Error, unknown argument was given: %s\n", args.OptionText());
        } else if (eso_state == SO_ARG_MISSING) {
            _tprintf(L"Error, missing argument was given for: %s\n", args.OptionText());
        }
    }

    if (eso_state != SO_SUCCESS) {
        printUsage();
        return 1;
    }

	if (name_bytes_copied == 0) {
		memcpy(target_section_name, ".end", name_size);
	}

    wchar_t drive[_MAX_DRIVE];
    wchar_t directory[_MAX_DIR];
    wchar_t file_name[_MAX_FNAME];
    wchar_t extension[_MAX_EXT];
    _tsplitpath_s(target_filepath, 
		drive, _MAX_DRIVE, 
		directory, _MAX_DIR, 
		file_name, _MAX_FNAME, 
		extension, _MAX_EXT);

	PortableExecutableEditor *editor;

	try {
		editor = &PortableExecutableEditor(target_filepath);
		_tprintf(L"* Loaded executable file %s%s into buffer.\n", file_name, extension);
	} catch (std::runtime_error) {
		_tprintf(L"! Error, could not open the executable file: %s%s\n", file_name, extension);
		return 1;
	}

    if (editor->ModifyFile(target_section_name)) {
        return 1;
    } else {
		_tprintf(L"* Modified buffer for executable file %s%s.\n", file_name, extension);
    }

    if (editor->SaveFile()) {
        return 1;
    } else {
		_tprintf(L"* The changes to the executable file have been saved.\n");
    }

    return 0;
}