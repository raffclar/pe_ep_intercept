#include <iostream>
#include "Editor.hpp"
#include "Assembly.hpp"
#include "Assembler.hpp"
#include "PePatchX64.hpp"

namespace Interceptor {
    bool Editor::edit(const std::string &in_path, const std::string &out_path, const std::string &section) {
        std::unique_ptr<Interceptor::PePatchX64> patcher;

        std::fstream file;
        file.exceptions(std::fstream::failbit | std::ios::badbit);
        file.open(
                in_path,
                std::ios::binary |
                std::ios::ate |
                std::ios::in |
                std::ios::out
        );

        PeFile exe_file(file);
        file.close();

        if (exe_file.hasSection(section)) {
            std::cout << "The executable already has the section \"" << section << "\"." << std::endl;
            return false;
        }

        Assembler assembler;
        auto arch = exe_file.getPeArch();

        switch (arch) {
            case Architecture::x64:
                patcher = std::make_unique<Interceptor::PePatchX64>(assembler, exe_file);
                break;
            default:
                std::cout << "The executable has an unsupported architecture." << std::endl;
                return false;
        }

        auto patched_file = patcher->patch(section);
        std::fstream output(out_path, std::ios::out | std::ios::trunc | std::ios::binary);
        patched_file.write(output);

        return true;
    }
}