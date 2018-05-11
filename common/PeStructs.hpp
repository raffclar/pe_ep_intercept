#ifndef PE_EP_INTERCEPT_PESTRUCTS_HPP
#define PE_EP_INTERCEPT_PESTRUCTS_HPP

namespace Interceptor {
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
    } DosHeader, *DosHeaderPtr;

    typedef struct {
        uint16_t machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
    } CoffHeader, *CoffHeaderPtr;

    typedef struct {
        uint32_t VirtualAddress;
        uint32_t Size;
    } DataDirectory, *DataDirectoryPtr;

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
    } OptionalHeaderX86, *OptionalHeaderX86Ptr;

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
        uint64_t SizeOfStackReserve;
        uint64_t SizeOfStackCommit;
        uint64_t SizeOfHeapReserve;
        uint64_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
        DataDirectory dataDirectory[directory_count];
    } OptionalHeaderX64, *OptionalHeaderX64Ptr;

    typedef struct {
        uint32_t signature;
        CoffHeader coff;
        OptionalHeaderX86 optional;
    } NtHeaderX86, *NtHeaderX86Ptr;

    typedef struct {
        uint32_t signature;
        CoffHeader coff;
        OptionalHeaderX64 optional;
    } NtHeaderX64, *NtHeaderX64Ptr;

    typedef struct {
        uint8_t Name[section_name_size];
        union {
            uint32_t PhysicalAddress;
            uint32_t VirtualSize;
        } Misc;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
    } SectionHeader, *SectionHeaderPtr;

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
