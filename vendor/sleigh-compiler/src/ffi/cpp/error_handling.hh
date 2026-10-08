#pragma once

#include "error.hh"
#include "loadimage.hh"
#include "translate.hh"
#include "xml.hh"

namespace rust {
    namespace behavior {
        template <typename Try, typename Fail>
        static void trycatch(Try &&func, Fail &&fail) noexcept {
            try {
                func();
            } catch (const ghidra::LowlevelError &e) {
                // Top-level error
                fail("LowlevelError: " + e.explain);
            } catch (const ghidra::DecoderError &e) {
                // Top-level error thrown by XML parser
                fail("DecoderError: " + e.explain);
            } catch (const std::exception &e) {
                fail(e.what());
            }
        }
    } // namespace behavior
} // namespace rust
