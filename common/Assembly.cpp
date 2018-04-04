#include "Assembly.hpp"

namespace Interceptor {
    std::string entryRedirectAssemblyX64(uint32_t oep) {
        std::string address = std::to_string(oep);

        return "push rbp;"
                       "mov rbp, rsp;"
                       "sub rsp, 24;"
                       "mov [rbp - 8], rax;"
                       // Peb
                       "mov rax, 60h;"
                       "mov rdx, gs:[rax];"
                       "mov [rbp - 16], rdx;"
                       // Ldr
                       "mov rcx, [rdx + 18h];"
                       "mov [rbp - 24], rcx;"
                       // In memory order module linked-list
                       "mov rax, [rcx + 10h];"
                       // Entry point
                       "mov rdx, [rax + 38h];"
                       "search:"
                       "cmp rdx, 0;"
                       "je finish;"
                       "mov rcx, [rbp - 8];"
                       // Check if entry point of module matches
                       // our program entry point
                       "cmp rdx, rcx;"
                       "je found;"
                       // Flink (next module)
                       "mov rax, [rax];"
                       // Next entry point
                       "mov rdx, [rax + 38h];"
                       "jmp search;"
                       "found:"
                       // Image base
                       "mov rdx, [rax + 30h];"
                       "mov rax, " + address + ";"
                       "add rdx, rax;"
                       "jmp rdx;"
                       "finish:"
                        // This will crash until we
                        // patch in ExitProcess
                       "ret;";
    }

    std::string entryRedirectAssemblyX86(uint32_t oep) {
        std::string address = std::to_string(oep);
        
        return "push ebp;"
                       "mov ebp, esp;"
                       "sub esp, 12;"
                       "sub [ebp - 4], eax;"
                       // Peb
                       "mov eax, 30h;"
                       "mov edx, fs:[eax];"
                       "mov [ebp - 8], edx;"
                       // Ldr
                       "mov ecx, [edx + 12h];"
                       "mov [ebp - 12], ecx;"
                       // In memory order module linked-list
                       "mov eax, [ecx + 08h];"
                       // Entry point
                       "mov edx, [eax + 1ch];"
                       "search:"
                       "cmp edx, 0;"
                       "je finish;"
                       "mov ecx, [ebp - 4];"
                       // Check if entry point of module matches
                       // our program entry point
                       "cmp edx, ecx;"
                       "je found;"
                       // Flink (next module)
                       "mov eax, [eax];"
                       // Next entry point
                       "mov edx, [eax + 1ch];"
                       "jmp search;"
                       "found:"
                       // Image base
                       "mov edx, [eax + 18h];"
                       "mov eax, " + address + ";"
                       "add edx, eax;"
                       "jmp edx;"
                       "finish:"
                       // This will crash until we
                       // patch in ExitProcess
                       "ret;";
    }
} // namespace Interceptor
