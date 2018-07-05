#ifndef PE_EP_INTERCEPT_EDITOR_HPP
#define PE_EP_INTERCEPT_EDITOR_HPP

#include "PeFile.hpp"

namespace Interceptor {
    class Editor {
    private:
        static PeFile original(std::fstream &file);
    public:
        /**
         *
         * @param file The stream contents will be used to instantiate a PeFile object
         * @param section The new section will have this string as its name
         * @return Contains a success. Returns original file on failure, patched on success
         */
        static std::tuple<PeFile, bool> edit(
                std::fstream &file,
                const std::string &section
        );
    };
}


#endif //PE_EP_INTERCEPT_EDITOR_HPP
