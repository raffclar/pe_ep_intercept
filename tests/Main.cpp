#define CATCH_CONFIG_MAIN
#include "utils/catch.hpp"
#include "../common/Editor.hpp"
#include <array>
#include <boost/iostreams/stream.hpp>
#include <boost/process.hpp>
#include <boost/filesystem.hpp>
#include <VersionHelpers.h>

namespace io = boost::iostreams;
namespace bp = boost::process;
namespace fs = boost::filesystem;

using namespace Interceptor;

std::string vcvars64 = R"("C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat")";
std::string msvc_cmd = vcvars64 + "&& cl.exe";

bool compile(const std::string &file) {
    bp::basic_pipe<char> p;

    fs::path file_path(file);
	fs::path test_output(fs::current_path() / "test_output");
    fs::path exe_path(test_output / file_path.filename().replace_extension("exe"));
	fs::path object_path(test_output / file_path.filename().replace_extension("obj"));

	// "cmd *file.cpp* /Fe*ExeOutput* /Fo*ObjOutput*"
	std::string full_cmd = msvc_cmd + " " + file + " /Fe" + exe_path.string() + " /Fo" + object_path.string();
    bp::system(full_cmd, (bp::std_err & bp::std_out) > p);
    return fs::exists(exe_path);
};

int run(const std::string &file) {
	bp::basic_pipe<char> p;

	fs::path file_path(file);
	fs::path test_output(fs::current_path() / "test_output" / file_path);
	return bp::system(test_output.string(), (bp::std_err & bp::std_out) > p);
}

TEST_CASE( "Edited executables can be run", "[PeFile]" ) {
    SECTION("Run vcvars64.bat") {
        bp::basic_pipe<char> p;
        REQUIRE(bp::system(vcvars64.c_str(), (bp::std_err & bp::std_out) > p) == 0);
    }

    SECTION("Has MSVC installed") {
        bp::basic_pipe<char> p;
        REQUIRE(bp::system(msvc_cmd, (bp::std_err & bp::std_out) > p) == 0);
    }

    SECTION("Tests are running on Windows NT6.1+") {
        REQUIRE(IsWindows7OrGreater());
    }

    SECTION("Working directory is project root") {
		// Can't set the working directory using settings for Visual Studio with CMake
		// Bit of hack for getting the right working directory when debugging
		if (fs::current_path().leaf().string() != "pe_ep_intercept") {
			fs::path wd(__FILE__);
			fs::current_path(wd.parent_path().parent_path());
		}

        fs::path full_path(fs::current_path());
        REQUIRE(full_path.leaf() == "pe_ep_intercept");
    }

	SECTION("Clear existing executables") {
		fs::path test_output = fs::current_path() / "test_output";
		fs::remove(test_output / "*.exe");
	}

    SECTION("Compile t1") {
        compile("test_programs\\t1.cpp");
    }

    SECTION("Edit t1") {
        REQUIRE(Editor::edit(fs::current_path().string() + "/test_output/t1.exe", ".blob"));
    }

    SECTION("Run t1") {
		REQUIRE(run("t1.exe") == 0);
    }

    SECTION("Compile t2") {
        compile("test_programs\\t2.cpp");
    }

    SECTION("Edit t2") {
        REQUIRE(Editor::edit(fs::current_path().string() + "/test_output/t2.exe", ".blob"));
    }

    SECTION("Run t2") {
		REQUIRE(run("t2.exe") == 0);
    }

    SECTION("Compile t3") {
        compile("test_programs\\t3.cpp");
    }

    SECTION("Edit t3") {
        REQUIRE(Editor::edit(fs::current_path().string() + "/test_output/t3.exe", ".blob"));
    }

    SECTION("Run t3") {
		REQUIRE(run("t3.exe") == 0);
    }
}

