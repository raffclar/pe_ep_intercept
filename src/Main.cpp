﻿#include <iostream>
#include <vector>
#include "utils/SimpleOpt.h"
#include "../common/PeFile.hpp"
#include "../common/Editor.hpp"

enum {
    OPT_HELP, OPT_IN, OPT_OUT, OPT_SECT
};

CSimpleOpt::SOption g_rgOptions[] = {
        {OPT_IN, "-p", SO_REQ_SEP},
        {OPT_SECT, "-s", SO_REQ_SEP},
        {OPT_OUT, "-o", SO_REQ_SEP},
        {OPT_SECT, "--section", SO_REQ_SEP},
        {OPT_HELP, "-h", SO_NONE},
        {OPT_HELP, "--help", SO_NONE},
        SO_END_OF_OPTIONS
};

void PrintUsage() {
    std::cout << "Usage: pe_ep_intercept.exe "
            "[-p PATH] [-s SECTION_NAME] [-o PATH]"
            "[--section SECTION_NAME] [-h] [--help]" << std::endl;
}

int main(int argc, char *argv[]) {
    std::cout << "pe_ep_intercept" << std::endl;

    if (argc < 3) {
        PrintUsage();
        return 0;
    }

    CSimpleOpt args(argc, argv, g_rgOptions, SO_O_EXACT);

    std::string section;
    std::string in;
    std::string out;
    _ESOError eso_state = SO_SUCCESS;

    while (args.Next() && eso_state == SO_SUCCESS) {
        eso_state = args.LastError();

        if (eso_state == SO_SUCCESS) {
            switch (args.OptionId()) {
                case OPT_HELP:
                    PrintUsage();
                    return 0;
                case OPT_IN:
                    in = args.OptionArg();
                    break;
                case OPT_SECT:
                    section = args.OptionArg();
                    break;
                case OPT_OUT:
                    out = args.OptionArg();
                    break;
                default:
                    break;
            }
        } else if (eso_state == SO_OPT_INVALID) {
            std::cout <<
                      "Error: unknown option was given: "
                      << args.OptionText() << std::endl;
        } else if (eso_state == SO_ARG_MISSING) {
            std::cout <<
                      "Error: missing argument was given for: "
                      << args.OptionText() << std::endl;
        }
    }

    if (eso_state != SO_SUCCESS) {
        PrintUsage();
        return 1;
    }

    if (in.empty()) {
        std::cout << "Error: input must be specified." << std::endl;
        PrintUsage();
        return 1;
    }

    if (out.empty()) {
        std::cout << "Error: output must be specified." << std::endl;
        PrintUsage();
        return 1;
    }

    if (section.empty()) {
        section = ".code";
    }

    bool success = Interceptor::Editor::edit(in, out, section);

    return 0;
}
