# r2r test harness for r2sleigh plugin

R2R_JOBS ?= 4
R2R_TIMEOUT ?= 120
R2R_TMPDIR ?= /tmp/r2sleigh-r2r-tmp
R2R_RUST_FEATURES ?= all-archs

.PHONY: all ensure-tools build-bins link-bins install-plugin run

all: run

ensure-tools:
	@command -v r2 >/dev/null || { echo "r2 not found in PATH"; exit 1; }
	@command -v r2r >/dev/null || { echo "r2r not found in PATH"; exit 1; }
	@command -v jq >/dev/null || { echo "jq not found in PATH"; exit 1; }

build-bins:
	cd ../e2e && \
	gcc -O0 -g -fno-stack-protector -no-pie -o vuln_test vuln_test.c && \
	gcc -O0 -g -fno-stack-protector -no-pie -o stress_test stress_test.c -lm && \
	gcc -O2 -g -fno-stack-protector -no-pie -o stress_test_opt stress_test.c -lm && \
	if [ -f test_func.c ]; then gcc -O0 -g -o test_func test_func.c; fi && \
	if [ -f sym_test.c ]; then gcc -O0 -g -o sym_test sym_test.c; fi

link-bins: build-bins
	@mkdir -p bins
	@ln -sf ../../e2e/vuln_test bins/vuln_test
	@ln -sf ../../e2e/stress_test bins/stress_test
	@ln -sf ../../e2e/stress_test_opt bins/stress_test_opt
	@if [ -f ../e2e/test_func ]; then ln -sf ../../e2e/test_func bins/test_func; fi
	@if [ -f ../e2e/sym_test ]; then ln -sf ../../e2e/sym_test bins/sym_test; fi

install-plugin:
	$(MAKE) -C ../../r2plugin RUST_FEATURES=$(R2R_RUST_FEATURES) install

run: ensure-tools link-bins install-plugin
	@rm -rf "$(R2R_TMPDIR)"
	@mkdir -p "$(R2R_TMPDIR)"
	TMPDIR="$(R2R_TMPDIR)" TMP="$(R2R_TMPDIR)" TEMP="$(R2R_TMPDIR)" \
		r2r -t $(R2R_TIMEOUT) -j $(R2R_JOBS) -L db/extras
