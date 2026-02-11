#!/bin/bash
# setup-runner.sh — Bootstrap a self-hosted GitHub Actions runner for r2sleigh
#
# Run as root on the target machine:
#   curl -sSL <url-to-this-script> | bash
#
# Prerequisites: Ubuntu/Debian-based system with internet access.

set -euo pipefail

RUNNER_USER="gh-runner"
RUNNER_HOME="/home/${RUNNER_USER}"
RUNNER_DIR="${RUNNER_HOME}/actions-runner"
R2_VERSION="5.9.8"  # Pin radare2 version — update as needed

echo "=== r2sleigh CI Runner Setup ==="

# ── 1. System packages ─────────────────────────────────────────────
echo "[1/6] Installing system packages..."
apt-get update -qq
apt-get install -y -qq \
    build-essential gcc g++ make pkg-config \
    git curl wget jq \
    libssl-dev zlib1g-dev \
    python3 python3-pip \
    meson ninja-build cmake \
    2>/dev/null

# ── 2. Create runner user ──────────────────────────────────────────
echo "[2/6] Setting up runner user..."
if ! id "${RUNNER_USER}" &>/dev/null; then
    useradd -m -s /bin/bash "${RUNNER_USER}"
    echo "Created user ${RUNNER_USER}"
else
    echo "User ${RUNNER_USER} already exists"
fi

# ── 3. Install Rust (as runner user) ───────────────────────────────
echo "[3/6] Installing Rust toolchain..."
su - "${RUNNER_USER}" -c '
    if ! command -v rustup &>/dev/null; then
        curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.93.0
    fi
    source ~/.cargo/env
    rustup toolchain install 1.93.0
    rustup default 1.93.0
    rustup component add rustfmt clippy
    rustc --version
    cargo --version
'

# ── 4. Install radare2 ─────────────────────────────────────────────
echo "[4/6] Installing radare2 ${R2_VERSION}..."
if ! command -v r2 &>/dev/null || ! r2 -v 2>/dev/null | grep -q "${R2_VERSION}"; then
    TMPDIR=$(mktemp -d)
    cd "${TMPDIR}"
    git clone --depth 1 --branch "${R2_VERSION}" https://github.com/radareorg/radare2.git
    cd radare2
    sys/install.sh
    cd /
    rm -rf "${TMPDIR}"
    echo "radare2 installed: $(r2 -v 2>&1 | head -1)"
else
    echo "radare2 ${R2_VERSION} already installed"
fi

# Ensure pkg-config can find radare2
ldconfig

# ── 5. Install Z3 (needed by r2sym) ────────────────────────────────
echo "[5/6] Installing Z3 solver..."
if ! dpkg -l | grep -q libz3-dev; then
    apt-get install -y -qq libz3-dev 2>/dev/null || {
        echo "Warning: libz3-dev not in apt, building from source..."
        TMPDIR=$(mktemp -d)
        cd "${TMPDIR}"
        git clone --depth 1 https://github.com/Z3Prover/z3.git
        cd z3
        python3 scripts/mk_make.py
        cd build
        make -j$(nproc)
        make install
        cd /
        rm -rf "${TMPDIR}"
    }
fi

# ── 6. Verify everything ───────────────────────────────────────────
echo "[6/6] Verifying installation..."
echo "  gcc:     $(gcc --version | head -1)"
echo "  r2:      $(r2 -v 2>&1 | head -1)"
echo "  pkg-config r_anal: $(pkg-config --modversion r_anal 2>/dev/null || echo 'NOT FOUND')"
su - "${RUNNER_USER}" -c 'source ~/.cargo/env && echo "  rustc:   $(rustc --version)" && echo "  cargo:   $(cargo --version)"'

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Download the GitHub Actions runner:"
echo "     mkdir -p ${RUNNER_DIR}"
echo "     cd ${RUNNER_DIR}"
echo "     curl -o actions-runner.tar.gz -L https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64-2.331.0.tar.gz"
echo "     tar xzf actions-runner.tar.gz"
echo "     chown -R ${RUNNER_USER}:${RUNNER_USER} ${RUNNER_DIR}"
echo ""
echo "  2. Configure (as ${RUNNER_USER}):"
echo "     su - ${RUNNER_USER}"
echo "     cd ~/actions-runner"
echo "     ./config.sh --url https://github.com/0verflowme/r2sleigh --token <YOUR_TOKEN>"
echo ""
echo "  3. Install as service (as root):"
echo "     cd ${RUNNER_DIR}"
echo "     ./svc.sh install ${RUNNER_USER}"
echo "     ./svc.sh start"
echo ""
