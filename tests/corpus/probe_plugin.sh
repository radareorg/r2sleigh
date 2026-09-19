#!/usr/bin/env bash
# Put the plugin built with symbols where radare2 loads it, or put the release
# build back.
#
# usage: tests/corpus/probe_plugin.sh install|restore|status
#
# `install` builds `[profile.probe]` (full debug info, opt-level 1), copies it
# over the installed plugin, signs it and writes its dSYM beside it, keeping
# the release build as <plugin>.release for `restore`. A debugger attached to
# radare2 then stops on source lines of the plugin. PLUGIN_DIR names the
# plugin directory (default: the r2r one), RUST_FEATURES the plugin features.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
plugin_dir=${PLUGIN_DIR:-/tmp/r2sleigh-r2r-tmp/plugins}
features=${RUST_FEATURES:-all-archs}
installed=$plugin_dir/r2sleigh/libr2sleigh_plugin.dylib
release=$installed.release

case ${1:-} in
install)
    [[ -f $installed ]] || { echo "no installed plugin at $installed; run make -C tests/r2r install-plugin" >&2; exit 69; }
    (cd "$root" && cargo build --profile probe --features "$features" -p r2sleigh-plugin >&2)
    [[ -f $release ]] || cp "$installed" "$release"
    cp "$root/target/probe/libr2sleigh_plugin.dylib" "$installed"
    codesign -f -s - "$installed" 2>/dev/null
    dsymutil "$installed" -o "$installed.dSYM" >/dev/null 2>&1 || true
    echo "probe plugin installed at $installed (release kept at $release)"
    ;;
restore)
    [[ -f $release ]] || { echo "nothing to restore: no $release" >&2; exit 0; }
    # A plugin installed since the probe went in is the current release;
    # the saved copy is stale and the install stands.
    if [[ $installed -nt $release ]]; then
        rm -f "$release"
        rm -rf "$installed.dSYM"
        echo "a newer plugin was installed since; kept it"
        exit 0
    fi
    mv "$release" "$installed"
    codesign -f -s - "$installed" 2>/dev/null
    rm -rf "$installed.dSYM"
    echo "release plugin restored at $installed"
    ;;
status)
    if [[ -f $release ]]; then echo "probe plugin installed"; else echo "release plugin installed"; fi
    ;;
*)
    echo "usage: $0 install|restore|status" >&2
    exit 64
    ;;
esac
