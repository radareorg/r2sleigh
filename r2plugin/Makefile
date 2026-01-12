# r2sleigh radare2 plugin Makefile

# Build configuration
RUST_TARGET ?= release
RUST_FEATURES ?= x86

# Paths
PLUGIN_NAME = anal_sleigh
RUST_LIB = libr2sleigh_plugin
RUST_BUILD_DIR = ../target/$(RUST_TARGET)

# Detect OS
UNAME := $(shell uname)
ifeq ($(UNAME),Darwin)
  RUST_LIB_EXT = dylib
  PLUGIN_EXT = dylib
  LDFLAGS_OS = -Wl,-rpath,@loader_path
else
  RUST_LIB_EXT = so
  PLUGIN_EXT = so
  LDFLAGS_OS = -Wl,-rpath,'$$ORIGIN'
endif

# radare2 configuration
R2_CFLAGS := $(shell pkg-config --cflags r_anal 2>/dev/null || echo "-I/usr/include/libr")
R2_LDFLAGS := $(shell pkg-config --libs r_anal 2>/dev/null || echo "-lr_anal -lr_util -lr_io")
R2_PLUGIN_DIR := $(shell r2 -H R2_USER_PLUGINS 2>/dev/null || echo "$(HOME)/.local/share/radare2/plugins")

# Compiler settings
CC ?= gcc
CFLAGS = -Wall -Wextra -fPIC -shared $(R2_CFLAGS)
LDFLAGS = $(R2_LDFLAGS) -L$(RUST_BUILD_DIR) -lr2sleigh_plugin $(LDFLAGS_OS)

# Output
PLUGIN_SO = $(PLUGIN_NAME).$(PLUGIN_EXT)

.PHONY: all clean install uninstall rust rust-debug rust-release help

all: $(PLUGIN_SO)

# Build the plugin shared object
$(PLUGIN_SO): r_anal_sleigh.c $(RUST_BUILD_DIR)/$(RUST_LIB).$(RUST_LIB_EXT)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build Rust library (release)
rust-release:
	cd .. && cargo build --release --features $(RUST_FEATURES) -p r2sleigh-plugin

# Build Rust library (debug)
rust-debug:
	cd .. && cargo build --features $(RUST_FEATURES) -p r2sleigh-plugin

# Default rust target
ifeq ($(RUST_TARGET),release)
rust: rust-release
$(RUST_BUILD_DIR)/$(RUST_LIB).$(RUST_LIB_EXT): rust-release
else
rust: rust-debug
$(RUST_BUILD_DIR)/$(RUST_LIB).$(RUST_LIB_EXT): rust-debug
endif

# Install plugin
install: $(PLUGIN_SO)
	@mkdir -p $(R2_PLUGIN_DIR)
	cp $(PLUGIN_SO) $(R2_PLUGIN_DIR)/
	cp $(RUST_BUILD_DIR)/$(RUST_LIB).$(RUST_LIB_EXT) $(R2_PLUGIN_DIR)/
	@echo "Installed to $(R2_PLUGIN_DIR)"

# Uninstall plugin
uninstall:
	rm -f $(R2_PLUGIN_DIR)/$(PLUGIN_SO)
	rm -f $(R2_PLUGIN_DIR)/$(RUST_LIB).$(RUST_LIB_EXT)
	@echo "Uninstalled from $(R2_PLUGIN_DIR)"

# Clean build artifacts
clean:
	rm -f $(PLUGIN_SO)

# Full clean including Rust
distclean: clean
	cd .. && cargo clean

# Help
help:
	@echo "r2sleigh radare2 plugin build"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build the plugin (default)"
	@echo "  rust         - Build only the Rust library"
	@echo "  install      - Install plugin to radare2 plugins dir"
	@echo "  uninstall    - Remove plugin from radare2 plugins dir"
	@echo "  clean        - Remove build artifacts"
	@echo "  distclean    - Remove all build artifacts including Rust"
	@echo ""
	@echo "Variables:"
	@echo "  RUST_TARGET   - 'release' (default) or 'debug'"
	@echo "  RUST_FEATURES - Sleigh features: 'x86' (default), 'arm', 'all-archs'"
	@echo ""
	@echo "Examples:"
	@echo "  make                           # Build release with x86"
	@echo "  make RUST_FEATURES=all-archs   # Build with all architectures"
	@echo "  make RUST_TARGET=debug         # Build debug version"
	@echo "  make install                   # Install to r2 plugins"
