#ifndef PE_EP_INTERCEPT_EDITOR_HPP
#define PE_EP_INTERCEPT_EDITOR_HPP

namespace Interceptor {
    class Editor {
    public:
        static bool edit(const std::string &in_path, const std::string &out_path, const std::string &section);
    };
}


#endif //PE_EP_INTERCEPT_EDITOR_HPP
