#ifndef PE_EP_INTERCEPT_PEPATCHX64_HPP
#define PE_EP_INTERCEPT_PEPATCHX64_HPP

#include "PeFile.hpp"
#include "Assembler.hpp"
#include "PePatch.hpp"

namespace Interceptor {
    class PePatchX64 : public PePatch {
    private:
        void addSection(const std::string &name) override;
    public:
        explicit PePatchX64(const Assembler &assembler, const PeFile &file) : PePatch(assembler, file) {};
        PeFile patch();
    };
}


#endif //PE_EP_INTERCEPT_PEPATCHX64_HPP
