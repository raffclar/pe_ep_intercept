#ifndef PE_EP_INTERCEPT_PESTRUCTS_HPP
#define PE_EP_INTERCEPT_PESTRUCTS_HPP

namespace Interceptor {
    const uint32_t scn_code = 0x00000020;
    const uint32_t scn_mem_exe = 0x20000000;
    const uint32_t scn_mem_read = 0x40000000;
    const uint32_t scn_mem_write = 0x80000000;

	const uint32_t directory_count = 16;
	const uint32_t section_name_size = 8;
	const uint16_t x86 = 0x014C;
	const uint16_t x64 = 0x8664;
	const uint16_t dos_signature = 0x5A4D;

    const int directory_import_index = 1;
    const int directory_resource_index = 2;
    const int directory_relocation_index = 3;
    const int directory_debug_index = 4;
    const int directory_tls_index = 5;

    const uint32_t ordinal_flag_x86 = 0x80000000;
    const uint64_t ordinal_flag_x64 = 0x8000000000000000;

	typedef struct {
		uint8_t e_magic[2];
		uint16_t e_cblp;
		uint16_t e_cp;
		uint16_t e_crlc;
		uint16_t e_cparhdr;
		uint16_t e_minalloc;
		uint16_t e_maxalloc;
		uint16_t e_ss;
		uint16_t e_sp;
		uint16_t e_csum;
		uint16_t e_ip;
		uint16_t e_cs;
		uint16_t e_lfarlc;
		uint16_t e_ovno;
		uint16_t e_res[4];
		uint16_t e_oemid;
		uint16_t e_oeminfo;
		uint16_t e_res2[10];
		int32_t e_lfanew;
	} DosHeader;

	typedef struct {
		uint16_t machine;
		uint16_t number_of_sections;
		uint32_t time_date_stamp;
		uint32_t pointer_to_symbol_table;
		uint32_t number_of_symbols;
		uint16_t sizeof_optional_header;
		uint16_t characteristics;
	} CoffHeader;

	typedef struct {
		uint32_t virtual_address;
		uint32_t size;
	} DataDirectory;

	typedef struct {
		uint16_t magic;
		uint8_t major_linker_version;
		uint8_t minor_linker_version;
		uint32_t size_of_code;
		uint32_t sizeof_initialized_data;
		uint32_t sizeof_uninitialized_data;
		uint32_t address_of_entry_point;
		uint32_t base_of_code;
		// Extensions
		uint32_t base_of_data;
		uint32_t image_base;
		uint32_t section_alignment;
		uint32_t file_alignment;
		uint16_t major_operating_system_version;
		uint16_t minor_operating_system_version;
		uint16_t major_image_version;
		uint16_t minor_image_version;
		uint16_t major_subsystem_version;
		uint16_t minor_subsystem_version;
		uint32_t win32_version_value;
		uint32_t sizeof_image;
		uint32_t sizeof_headers;
		uint32_t checksum;
		uint16_t subsystem;
		uint16_t dll_characteristics;
		uint32_t sizeof_stack_reserve;
		uint32_t sizeof_stack_commit;
		uint32_t sizeof_heap_reserve;
		uint32_t sizeof_heap_commit;
		uint32_t loader_flags;
		uint32_t number_of_rva_and_sizes;
		DataDirectory data_directory[directory_count];
	} OptionalHeaderX86;

	typedef struct {
		uint16_t magic;
		uint8_t major_linker_version;
		uint8_t minor_linker_version;
		uint32_t sizeof_code;
		uint32_t sizeof_initialized_data;
		uint32_t sizeof_uninitialized_data;
		uint32_t address_of_entry_point;
		// Extensions
		uint32_t base_of_code;
		uint64_t image_base;
		uint32_t section_alignment;
		uint32_t file_alignment;
		uint16_t major_operating_system_version;
		uint16_t minor_operating_system_version;
		uint16_t major_image_version;
		uint16_t minor_image_version;
		uint16_t major_subsystem_version;
		uint16_t minor_subsystem_version;
		uint32_t win32_version_value;
		uint32_t size_of_image;
		uint32_t size_of_headers;
		uint32_t checksum;
		uint16_t subsystem;
		uint16_t dll_characteristics;
		uint64_t sizeof_stack_reserve;
		uint64_t sizeof_stack_commit;
		uint64_t sizeof_heap_reserve;
		uint64_t sizeof_heap_commit;
		uint32_t loader_flags;
		uint32_t number_of_rva_and_sizes;
		DataDirectory data_directory[directory_count];
	} OptionalHeaderX64;

    typedef struct {
        uint32_t signature;
        CoffHeader coff;
        OptionalHeaderX86 optional;
    } NtHeaderX86;

    typedef struct {
        uint32_t signature;
        CoffHeader coff;
        OptionalHeaderX64 optional;
    } NtHeaderX64;

	typedef struct {
		uint8_t name[section_name_size];
		union {
			uint32_t physical_address;
			uint32_t virtual_size;
		} Misc;
		uint32_t virtual_address;
		uint32_t size_of_raw_data;
		uint32_t pointer_to_raw_data;
		uint32_t pointer_to_relocations;
		uint32_t pointer_to_line_numbers;
		uint16_t number_of_relocations;
		uint16_t number_of_line_numbers;
		uint32_t characteristics;
	} SectionHeader;

    typedef struct {
        uint32_t StartingAddress;
        uint32_t EndingAddress;
        uint32_t EndOfPrologue;
    } FunctionEntry, *FunctionEntryPtr;

    typedef struct {
        union {
            uint32_t Characteristics;
            uint32_t OriginalFirstThunk;
        };
        uint32_t TimeDateStamp;
        uint32_t ForwarderChain;
        uint32_t Name;
        uint32_t FirstThunk;
    } ImportDescriptor, *ImportDescriptorPtr;

    typedef struct {
        union {
            uint32_t ForwarderString;
            uint32_t Function;
            uint32_t Ordinal;
            uint32_t AddressOfData;
        } u1;
    } ThunkDataX86, *ThunkDataX86Ptr;

    typedef struct {
        uint16_t Hint;
        int8_t Name[1];
    } ImportByName, *ImportByNamePtr;
}


#endif //PE_EP_INTERCEPT_PESTRUCTS_HPP
