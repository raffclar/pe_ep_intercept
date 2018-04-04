#include <iostream>
#include "Editor.hpp"
#include "Assembly.hpp"
#include "Assembler.hpp"
#include "PePatchX64.hpp"

namespace Interceptor {
    bool Editor::edit(std::string file_path, const std::string &section) {
        std::unique_ptr<Interceptor::PePatchX64> patcher;

        std::fstream file_stream;
        file_stream.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        file_stream.open(
                file_path,
                std::ios::binary |
                std::ifstream::ate |
                std::fstream::in |
                std::fstream::out
        );

        std::streamsize size = file_stream.tellg();
        file_stream.seekg(0, std::ios::beg);

        if (size <= 0) {
            throw std::runtime_error("could not get file size");
        }

        std::vector<char> file_contents(size);

        if (!file_stream.read(file_contents.data(), size)) {
            throw std::runtime_error("could not read file");
        }

        std::string instruct;
        uint32_t oep = 0;

        Assembler assembler;
        PeFile file(file_contents);
        PeArch arch = file.getPeArch();

        switch (arch) {
            case Interceptor::PeArch::x64:
                patcher = std::make_unique<Interceptor::PePatchX64>(assembler, file);
                oep = file.getEntryPoint();
                instruct = Interceptor::entryRedirectAssemblyX64(oep);
                break;
            default:
                std::cout << "Unsupported architecture." << std::endl;
                return false;
        }

        if (file.hasSection(section)) {
            std::cout << "Has section \"" << section << "\"." << std::endl;
            return false;
        }

        file_contents = patcher->patch();

        file_stream.seekp(0);
        file_stream.write(file_contents.data(), file_contents.size());

        return true;
    }
}