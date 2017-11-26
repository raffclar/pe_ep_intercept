#ifndef PE_EP_INTERCEPT_PEPATCH_HPP
#define PE_EP_INTERCEPT_PEPATCH_HPP

#include "PeFile.hpp"

namespace PeEpIntercept {
    class PePatch : public PeFile {
    protected:
    public:
        explicit PePatch(std::string &path);
        virtual void AddSection(const std::string &name, uint32_t code_size) = 0;
        virtual void SaveFile(std::string new_path, std::vector<char> code_buffer) = 0;
    };
}


#endif //PE_EP_INTERCEPT_PEPATCH_HPP
