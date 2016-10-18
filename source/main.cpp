#include <iostream>
#include <string>
#include <vector>
#include <limits>

#include "ExeManager.h"

// https://github.com/brofield/simpleopt
// MIT license
#include "utils/SimpleOpt.h"

typedef std::basic_string<unsigned char> UString;

// These are assembly procedures
extern "C" {
	void Entry();
	void EntryEnd();
}

const char *default_section_name = ".end";
const unsigned char bytes[4] = { 0xC4, 0xC3, 0xC2, 0xC1 };

struct FilePath {
	wchar_t drive[_MAX_DRIVE];
	wchar_t directory[_MAX_DIR];
	wchar_t file_name[_MAX_FNAME];
	wchar_t extension[_MAX_EXT];
};

enum { OPT_HELP, OPT_PATH, OPT_SECT };

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

	wchar_t *target_filepath = NULL;
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
			_tprintf(L"* Error, unknown option was given: %s\n", args.OptionText());
		} else if (eso_state == SO_ARG_MISSING) {
			_tprintf(L"* Error, missing argument was given for: %s\n", args.OptionText());
		}
	}

	//TODO: Replace empty char array check with file path validator
	// Quit if the above parsing fails otherwise we validate the path argument
	if (eso_state != SO_SUCCESS) {
		printUsage();
		return 1;
	} else if (target_filepath[0] == '\0') {
		_tprintf(L"* Error, path cannot be empty.\n\n");
		printUsage();
		return 1;
	}

	if (name_bytes_copied == 0) {
		_tprintf(L"* No section name specified. Using \"%hs\".\n", default_section_name);
		memcpy(target_section_name, default_section_name, name_size);
	}

	FilePath file_path;
	_tsplitpath_s(target_filepath,
		file_path.drive, _MAX_DRIVE,
		file_path.directory, _MAX_DIR,
		file_path.file_name, _MAX_FNAME,
		file_path.extension, _MAX_EXT);

	ExeManager *exe_manager = NULL;

	try {
		exe_manager = &ExeManager(target_filepath);
		_tprintf(L"* Loaded executable file %s%s into buffer.\n", file_path.file_name, file_path.extension);
	} catch (std::runtime_error) {
		_tprintf(L"* Error, could not open the executable file: %s%s\n", file_path.file_name, file_path.extension);
		return 1;
	}

	char *code_buffer;
	DWORD code_size;

	try {
		code_size = ExeManager::CopyProcedure(code_buffer, Entry, EntryEnd);
		_tprintf(L"* Copied procedure into buffer.\n");
	} catch (std::runtime_error) {
		_tprintf(L"* Error, could not copy procedure.\n");
		return 1;
	}

	UString signature(bytes, bytes + 4);

	if (code_size <= signature.max_size()) {
		UString code_buffer_str(code_buffer, code_buffer + code_size);
		std::size_t index = code_buffer_str.find(signature);

		if (index != std::string::npos) {
			DWORD entry = exe_manager->GetOriginalEntryPoint();
			_tprintf(L"* Found signature, replacing with 0x%04x.\n", entry);
			memcpy(&code_buffer[index], &entry, sizeof(DWORD));
		} else {
			_tprintf(L"* Error, unable to find signature inside code buffer.\n");
			return 1;
		}
	} else {
		_tprintf(L"* Error, unable to change signature inside code buffer:\n");
		_tprintf(L"* Code buffer is too large to search.\n");
		return 1;
	}

	if (exe_manager->ModifyFile(target_section_name, code_size)) {
		return 1;
	} else {
		_tprintf(L"* Modified buffer for executable file %s%s.\n", file_path.file_name, file_path.extension);
	}

	if (exe_manager->SaveFile(code_buffer, code_size)) {
		return 1;
	} else {
		_tprintf(L"* The changes to the executable file have been saved.\n");
	}

	delete[] code_buffer;

	return 0;
}