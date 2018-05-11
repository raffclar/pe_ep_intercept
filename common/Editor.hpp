#ifndef PE_EP_INTERCEPT_EDITOR_HPP
#define PE_EP_INTERCEPT_EDITOR_HPP

namespace Interceptor {
    class Editor {
    public:
        static bool edit(std::string file_path, const std::string &section);
    };
}


#endif //PE_EP_INTERCEPT_EDITOR_HPP
