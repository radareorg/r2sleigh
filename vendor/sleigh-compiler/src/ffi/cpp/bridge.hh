#pragma once

#include <memory>

#include "error_handling.hh"
#include "slgh_compile.hh"

namespace ghidra {
    extern std::vector<std::string> *slgh_errors;
    extern std::vector<std::string> *slgh_warnings;
}

// Defined in cxx bridge in sys.rs
struct PreprocessorDefine;
struct CompileResponse;

class SleighCompileProxy : public ghidra::SleighCompile {
    public:
        void setAllOptionsProxy(const std::vector<PreprocessorDefine> &defines, bool unnecessaryPcodeWarning,
                bool lenientConflict, bool allCollisionWarning,
                bool allNopWarning, bool deadTempWarning, bool enforceLocalKeyWord,
                bool largeTemporaryWarning, bool caseSensitiveRegisterNames, bool debugOutput);
        CompileResponse run_compilation_proxy(const std::string &filein, const std::string &fileout);
};

std::unique_ptr<SleighCompileProxy> construct_new_sleigh_compile();
