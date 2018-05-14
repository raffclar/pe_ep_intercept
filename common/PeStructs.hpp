#ifndef PE_EP_INTERCEPT_PESTRUCTS_HPP
#define PE_EP_INTERCEPT_PESTRUCTS_HPP

namespace Interceptor { namespace RawHeaders {
    const uint32_t scn_code = 0x00000020;
    const uint32_t scn_mem_exe = 0x20000000;
    const uint32_t scn_mem_read = 0x40000000;
    const uint32_t scn_mem_write = 0x80000000;

    const int directory_count = 16;
    const int section_name_size = 8;

    const int directory_import_index = 1;
    const int directory_resource_index = 2;
    const int directory_relocation_index = 3;
    const int directory_debug_index = 4;
    const int directory_tls_index = 5;

    const uint32_t ordinal_flag_x86 = 0x80000000;
    const uint64_t ordinal_flag_x64 = 0x8000000000000000;

    const uint16_t dos_signature = 0x5A4D;
    const uint16_t nt_signature = 0x4550;

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
        uint32_t time_datestamp;
        uint32_t pointer_to_symbol_table;
        uint32_t number_of_symbols;
        uint16_t size_of_optional_header;
        uint16_t characteristics;
    } CoffHeader;

    typedef struct {
        uint32_t VirtualAddress;
        uint32_t Size;
    } DataDirectory;

    typedef struct {
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        // Extensions
        uint32_t BaseOfData;
        uint32_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint32_t SizeOfStackReserve;
        uint32_t SizeOfStackCommit;
        uint32_t SizeOfHeapReserve;
        uint32_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
        DataDirectory dataDirectory[directory_count];
    } OptionalHeaderX86;

    typedef struct {
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        // Extensions
        uint32_t BaseOfCode;
        uint64_t ImageBase;
        uint32_t section_alignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint64_t SizeOfStackReserve;
        uint64_t SizeOfStackCommit;
        uint64_t SizeOfHeapReserve;
        uint64_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
        DataDirectory dataDirectory[directory_count];
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
        } misc;
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
    } FunctionEntry;

    typedef struct {
        union {
            uint32_t Characteristics;
            uint32_t OriginalFirstThunk;
        };
        uint32_t TimeDateStamp;
        uint32_t ForwarderChain;
        uint32_t Name;
        uint32_t FirstThunk;
    } ImportDescriptor;

    typedef struct {
        union {
            uint32_t ForwarderString;
            uint32_t Function;
            uint32_t Ordinal;
            uint32_t AddressOfData;
        } u1;
    } ThunkDataX86;

    typedef struct {
        uint16_t Hint;
        int8_t Name[1];
    } ImportByName;
} }


#endif //PE_EP_INTERCEPT_PESTRUCTS_HPP
