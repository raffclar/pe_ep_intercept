#include <iostream>
#include "Editor.hpp"
#include "Assembler.hpp"
#include "PePatchX64.hpp"

namespace Interceptor {
    PeFile Editor::original(std::fstream &file) {
        try {
            return PeFile(file);
        } catch (std::runtime_error &ex) {
            auto message = std::string("Could not parse the file. Reason: \"") + ex.what() + "\".";
            throw std::runtime_error(message);
        }
    }

    std::tuple<PeFile, bool> Editor::edit(
            std::fstream &file,
            const std::string &section
    ) {
        std::unique_ptr<Interceptor::PePatchX64> patcher;
        auto exe_file = original(file);

        if (exe_file.hasSection(section)) {
            std::cout << "The executable already has the section \"" << section << "\"." << std::endl;
            return std::make_tuple(exe_file, false);
        }

        Assembler assembler;
        auto arch = exe_file.getPeArch();

        switch (arch) {
            case Architecture::x64:
                patcher = std::make_unique<Interceptor::PePatchX64>(assembler, exe_file);
                break;
            default:
                std::cout << "The executable has an unsupported architecture." << std::endl;
                return std::make_tuple(exe_file, false);
        }

        auto patched_file = patcher->patch(section);
        return std::make_tuple(patched_file, true);
    }
}