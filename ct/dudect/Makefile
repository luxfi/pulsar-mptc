# Pulsar-M constant-time analysis harness — dudect bridge.
#
# Builds the cgo shim libraries (libpulsarm_verify, libpulsarm_combine)
# and links the C dudect harnesses against them.
#
# Prereqs (run once):
#   ./fetch.sh           # pulls dudect.h at the pinned commit
#
# Build:
#   make                 # both verify + combine
#   make verify          # just verify
#   make combine         # just combine
#
# Run:
#   ./dudect_verify      # smoke test (10000 samples/batch x 4 batches)
#   ./dudect_combine     # smoke test (2000 samples/batch x 4 batches)
#
# Full submission run (10^9 samples on a pinned-CPU quiet host):
#   DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_verify
#
# Hosts:
#   - x86_64 Linux/macOS: builds cleanly against upstream dudect.h
#   - aarch64 Linux/macOS: dudect_compat.h is force-included to supply
#     ARM equivalents of _mm_mfence() / __rdtsc(); see header for the
#     accuracy disclaimer.

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Shared-library extension is .dylib on macOS, .so elsewhere.
ifeq ($(UNAME_S),Darwin)
    SHLIB_EXT := dylib
    RPATH_FLAG := -Wl,-rpath,@loader_path
else
    SHLIB_EXT := so
    RPATH_FLAG := -Wl,-rpath,'$$ORIGIN'
endif

# Source paths.
REPO_ROOT := $(shell cd ../.. && pwd)
DUDECT_HDR := dudect/src/dudect.h

# C compile flags. -O2 is the default per dudect's own build; the
# leakage signal is preserved at -O2 because the inner do_one_computation
# call boundary is opaque to the compiler.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wno-unused-parameter -I. -Idudect/src
LDFLAGS ?=
LDLIBS  := -lm

# Force-include the ARM compat shim on AArch64 hosts so dudect.h's
# x86 intrinsics resolve. On x86 we skip the shim.
ifeq ($(UNAME_M),arm64)
    CFLAGS += -include dudect_compat.h
endif
ifeq ($(UNAME_M),aarch64)
    CFLAGS += -include dudect_compat.h
endif

# Go env. GOWORK=off matches scripts/test.sh — this repo uses a
# single-module layout and a stray go.work in any parent confuses
# the toolchain.
GO     ?= go
GOENV  := GOWORK=off CGO_ENABLED=1

.PHONY: all verify combine clean check-dudect

all: verify combine

# Build the cgo shim into a host-platform shared library, then link
# the C harness against it. The Go build emits both the .{dylib,so}
# and a generated header (libpulsarm_verify.h) that we ignore — the
# C harness uses its own extern declarations because they're the
# same three symbols every time and editing two files instead of one
# is simpler than chasing cgo's header generation rules.

libpulsarm_verify.$(SHLIB_EXT): verify_ct.go check-dudect
	$(GOENV) $(GO) build -buildmode=c-shared \
		-o libpulsarm_verify.$(SHLIB_EXT) \
		./verify_ct.go

libpulsarm_combine.$(SHLIB_EXT): combine_ct.go check-dudect
	$(GOENV) $(GO) build -buildmode=c-shared \
		-o libpulsarm_combine.$(SHLIB_EXT) \
		./combine_ct.go

dudect_verify: dudect_verify.c libpulsarm_verify.$(SHLIB_EXT) $(DUDECT_HDR)
	$(CC) $(CFLAGS) -o dudect_verify dudect_verify.c \
		-L. -lpulsarm_verify $(LDFLAGS) $(LDLIBS) $(RPATH_FLAG)

dudect_combine: dudect_combine.c libpulsarm_combine.$(SHLIB_EXT) $(DUDECT_HDR)
	$(CC) $(CFLAGS) -o dudect_combine dudect_combine.c \
		-L. -lpulsarm_combine $(LDFLAGS) $(LDLIBS) $(RPATH_FLAG)

verify: dudect_verify
combine: dudect_combine

check-dudect:
	@if [ ! -f $(DUDECT_HDR) ]; then \
		echo "==> dudect.h missing — run ./fetch.sh"; \
		exit 1; \
	fi

clean:
	rm -f dudect_verify dudect_combine
	rm -f libpulsarm_verify.$(SHLIB_EXT) libpulsarm_verify.h
	rm -f libpulsarm_combine.$(SHLIB_EXT) libpulsarm_combine.h
