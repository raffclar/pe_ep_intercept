#include <keystone/include/keystone/keystone.h>
#include "Assembler.hpp"

namespace Interceptor {
    std::vector<char> Assembler::assemble(Architecture type, const std::string &assembly) {
        std::vector<char> instructions;

        if (assembly.empty()) {
            return instructions;
        }

        unsigned char *encode = nullptr;
        ks_engine *ks = nullptr;
        size_t count;
        size_t size;

        auto code_deleter = [](unsigned char *code_ptr) {
            ks_free(code_ptr);
        };

        auto ks_deleter = [](ks_engine *ks_ptr) {
            ks_close(ks_ptr);
        };

        ks_mode instruct_mode;

        switch (type) {
            case Architecture::x86:
                instruct_mode = KS_MODE_32;
                break;
            case Architecture::x64:
                instruct_mode = KS_MODE_64;
                break;
            default:
                throw std::runtime_error("Executable type not supported");
        }

        if (ks_open(KS_ARCH_X86, instruct_mode, &ks) != KS_ERR_OK) {
            throw std::runtime_error("Failed to open keystone");
        }

        std::unique_ptr<ks_engine[], decltype(ks_deleter)> ks_ptr(ks, ks_deleter);

        if (ks_asm(ks, assembly.c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
            throw std::runtime_error("Failed to assemble instructions");
        }

        std::unique_ptr<unsigned char[],
                decltype(code_deleter)> encode_ptr(encode, code_deleter);

        if (size > sizeof(uint32_t) * 0xff) {
            throw std::runtime_error("Exceeded max section size");
        }

        for (auto i = 0; i < size; i++) {
            auto encoded = static_cast<char>(encode[i]);
            instructions.push_back(encoded);
        }

        return instructions;
    }
}
