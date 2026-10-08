#include <mutex>

#include "bridge.hh"
#include "rust/cxx.h"
#include "sleigh-compiler/src/ffi/sys.rs.h"

void SleighCompileProxy::setAllOptionsProxy(
        const std::vector<PreprocessorDefine> &defines, bool unnecessaryPcodeWarning,
        bool lenientConflict, bool allCollisionWarning,
        bool allNopWarning,bool deadTempWarning,bool enforceLocalKeyWord,
        bool largeTemporaryWarning, bool caseSensitiveRegisterNames, bool debugOutput) {

    std::map<std::string, std::string> definesMap;
    for (auto &d : defines) {
        definesMap.emplace(d.name, d.value);
    }

    setAllOptions(definesMap, unnecessaryPcodeWarning,
        lenientConflict, allCollisionWarning,
        allNopWarning, deadTempWarning, enforceLocalKeyWord,
        largeTemporaryWarning, caseSensitiveRegisterNames, debugOutput);
}

CompileResponse SleighCompileProxy::run_compilation_proxy(const std::string &filein, const std::string &fileout) {
    // The run_compilation call sets the global variable `slgh` in slgh_compile.cc. Guard with lock
    static std::mutex mutex;
    const std::lock_guard<std::mutex> lock(mutex);
    ghidra::int4 exitcode = run_compilation(filein, fileout);

    CompileResponse response { exitcode };
    if (ghidra::slgh_errors) {
        for (auto& err : *ghidra::slgh_errors) {
            response.errors.emplace_back(err);
        }
    }

    if (ghidra::slgh_warnings) {
        for (auto& warn : *ghidra::slgh_warnings) {
            response.warnings.emplace_back(warn);
        }
    }

    return response;
}

std::unique_ptr<SleighCompileProxy> construct_new_sleigh_compile() {
    return std::make_unique<SleighCompileProxy>();
}
