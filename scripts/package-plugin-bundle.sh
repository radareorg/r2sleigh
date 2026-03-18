#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/dist}"
RUST_FEATURES="${RUST_FEATURES:-all-archs}"
RUST_TARGET="${RUST_TARGET:-release}"
CARGO_TARGET_ROOT="${CARGO_TARGET_DIR:-${ROOT_DIR}/target}"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

detect_os() {
    case "$(uname -s)" in
        Linux)
            printf '%s\n' "linux"
            ;;
        Darwin)
            printf '%s\n' "macos"
            ;;
        *)
            echo "unsupported host OS: $(uname -s)" >&2
            exit 1
            ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64 | amd64)
            printf '%s\n' "x86_64"
            ;;
        arm64 | aarch64)
            printf '%s\n' "aarch64"
            ;;
        *)
            echo "unsupported host architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
}

detect_lib_ext() {
    case "$(uname -s)" in
        Linux)
            printf '%s\n' "so"
            ;;
        Darwin)
            printf '%s\n' "dylib"
            ;;
        *)
            echo "unsupported host OS for library extension: $(uname -s)" >&2
            exit 1
            ;;
    esac
}

write_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    else
        shasum -a 256 "$1"
    fi
}

main() {
    require_command make
    require_command r2
    require_command tar

    mkdir -p "${OUT_DIR}"

    local os arch lib_ext r2_version r2_abi asset_base bundle_name bundle_path checksum_path
    os="$(detect_os)"
    arch="$(detect_arch)"
    lib_ext="$(detect_lib_ext)"
    r2_version="$(r2 -H R2_VERSION)"
    r2_abi="$(r2 -H R2_ABIVERSION)"
    asset_base="r2sleigh-plugin-${os}-${arch}-r2abi${r2_abi}"
    bundle_name="${asset_base}.tar.gz"
    bundle_path="${OUT_DIR}/${bundle_name}"
    checksum_path="${bundle_path}.sha256"

    local bundle_root rust_lib anal_plugin arch_plugin
    stage_dir="$(mktemp -d "${TMPDIR:-/tmp}/r2sleigh-bundle.XXXXXX")"
    trap 'rm -rf "${stage_dir}"' EXIT
    bundle_root="${stage_dir}/r2sleigh-plugin"

    make -C "${ROOT_DIR}/r2plugin" clean
    make -C "${ROOT_DIR}/r2plugin" "RUST_TARGET=${RUST_TARGET}" "RUST_FEATURES=${RUST_FEATURES}"

    rust_lib="${CARGO_TARGET_ROOT}/${RUST_TARGET}/libr2sleigh_plugin.${lib_ext}"
    anal_plugin="${ROOT_DIR}/r2plugin/anal_sleigh.${lib_ext}"
    arch_plugin="${ROOT_DIR}/r2plugin/arch_sleigh.${lib_ext}"

    for file_path in "${rust_lib}" "${anal_plugin}" "${arch_plugin}"; do
        if [ ! -f "${file_path}" ]; then
            echo "missing expected build output: ${file_path}" >&2
            exit 1
        fi
    done

    mkdir -p "${bundle_root}"
    cp "${anal_plugin}" "${bundle_root}/"
    cp "${arch_plugin}" "${bundle_root}/"
    cp "${rust_lib}" "${bundle_root}/"

    cat > "${bundle_root}/manifest.json" <<EOF
{
  "name": "r2sleigh-plugin",
  "os": "${os}",
  "arch": "${arch}",
  "r2_version": "${r2_version}",
  "r2_abi": "${r2_abi}",
  "rust_target": "${RUST_TARGET}",
  "rust_features": "${RUST_FEATURES}",
  "files": [
    "anal_sleigh.${lib_ext}",
    "arch_sleigh.${lib_ext}",
    "libr2sleigh_plugin.${lib_ext}"
  ]
}
EOF

    rm -f "${bundle_path}" "${checksum_path}"
    tar -C "${stage_dir}" -czf "${bundle_path}" "r2sleigh-plugin"
    (
        cd "${OUT_DIR}"
        write_sha256 "${bundle_name}" > "${bundle_name}.sha256"
    )

    echo "created ${bundle_path}"
    echo "created ${checksum_path}"

    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        {
            echo "asset_base=${asset_base}"
            echo "artifact_name=${asset_base}"
            echo "bundle_name=${bundle_name}"
            echo "bundle_path=${bundle_path}"
            echo "checksum_path=${checksum_path}"
            echo "r2_version=${r2_version}"
            echo "r2_abi=${r2_abi}"
        } >> "${GITHUB_OUTPUT}"
    fi
}

main "$@"
