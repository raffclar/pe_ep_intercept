//
// Created by gavxn on 10/08/2017.
//

#include "PeAssembly.hpp"
#include <string>

namespace PeEpIntercept {
    std::string EntryRedirectAssemblyX64(uint32_t oep) {
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
                       // In load order module linked-list
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
                       "ret;";
    }

    std::string EntryRedirectAssemblyX86(uint32_t oep) {
        return "";
    }
}
