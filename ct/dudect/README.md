# Constant-time analysis (dudect)

dudect (https://github.com/oreparaz/dudect) is a black-box constant-time
checker. It runs a target operation on two classes of inputs (fixed +
random) and applies a Welch's t-test to the timing distributions. If
the test detects a statistically significant timing difference, the
target leaks information through wall-clock time.

This directory holds the Pulsar-M dudect harness. We measure two
operations:

1. **`pulsarm.Verify`** — the load-bearing entry point. Must be
   constant-time in the public key, message, and signature bytes.
2. **`pulsarm.Combine`** — the threshold aggregator. Must be
   constant-time in the per-party signature shares.

`pulsarm.Sign` is intentionally NOT constant-time per FIPS 204 §3.3 —
the rejection-sampling loop has secret-dependent retry count. This is
a property of ML-DSA itself, not Pulsar-M. Production deployments that
need constant-time Sign use the FIPS 204 "ext-ml-dsa-65-cs" context-
supplied variant (open question for MPTC); Pulsar-M inherits whatever
Sign property the underlying FIPS 204 implementation gives.

## Status

Harness layout: **wired**.

| File | Status |
|---|---|
| `verify_ct.go` | cgo bridge exposing `pulsarm.Verify` |
| `combine_ct.go` | cgo bridge exposing `pulsarm.Combine` |
| `dudect_verify.c` | dudect main loop driving Verify |
| `dudect_combine.c` | dudect main loop driving Combine |
| `dudect_compat.h` | AArch64 shim for `_mm_mfence` / `__rdtsc` |
| `Makefile` | host-platform build (Linux/macOS, x86_64/arm64) |
| `fetch.sh` | clones upstream dudect at pinned commit |
| `results/` | pinned harness output (smoke + submission runs) |

## Architecture

dudect is a single-header library with this contract:

```c
// User supplies:
void prepare_inputs(dudect_config_t *cfg, uint8_t *input, uint8_t *classes);
uint8_t do_one_computation(uint8_t *data);

// User drives:
dudect_init(&ctx, &cfg);
while (dudect_main(&ctx) == DUDECT_NO_LEAKAGE_EVIDENCE_YET) { /* loop */ }
dudect_free(&ctx);
```

`do_one_computation` MUST execute the target in constant time IF the
target is constant time. We achieve this with a thin cgo bridge:

```
+-------------------+        +-----------------------+        +----------+
|  dudect_verify.c  |  --->  |  libpulsarm_verify.*  |  --->  |  pulsarm |
|  (C main loop)    |  cgo   |  (verify_ct.go bridge)|  Go    |  .Verify |
+-------------------+        +-----------------------+        +----------+
```

The bridge holds a fixture (pk + valid signature on a fixed message)
built once at startup. `pulsarm_verify_ct(data)` copies `data` into a
fresh `*Signature` and calls `pulsarm.Verify(params, pk, msg, sig)`
— the result is discarded; dudect measures cycles around the call.

For Combine the bridge runs a real (n=3, t=2, ModeP65) DKG +
threshold-sign once at startup, then on each sample overwrites one
party's Round-2 PartialSig bytes with the caller's bytes before
invoking `pulsarm.Combine`.

### AArch64 compatibility

Upstream `dudect.h` uses x86 intrinsics (`_mm_mfence`, `__rdtsc`).
`dudect_compat.h` is force-included by the Makefile on `arm64` /
`aarch64` hosts and supplies equivalents using `dsb sy` + reads of
`CNTVCT_EL0`. The ARM generic timer ticks slower than RDTSC (typically
24 MHz on Apple Silicon vs ~3 GHz on x86) but the Welch t-test is
dimensionless in counter units — the constant-time verdict is the
same, just with a slightly different noise floor.

## Install dudect

dudect is NOT packaged by Homebrew or apt. Fetch from upstream:

```bash
./fetch.sh
```

This clones `https://github.com/oreparaz/dudect.git` into
`./dudect/`. The Makefile reads `./dudect/src/dudect.h`.

To pin a specific commit, edit `DUDECT_COMMIT` at the top of
`fetch.sh`.

## Build

```bash
make            # both harnesses
make verify     # just dudect_verify
make combine    # just dudect_combine
make clean
```

The Makefile detects host platform via `uname -s` (Darwin → `.dylib`,
elsewhere → `.so`) and `uname -m` (`arm64` / `aarch64` → include the
compat shim).

## Run

```bash
# Smoke test (default — 10000/2000 samples/batch × 4 batches):
./dudect_verify   2>results/verify.log
./dudect_combine  2>results/combine.log

# Larger budget (override via env):
DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=100 ./dudect_verify

# Full NIST submission budget (~10^9 samples). Pin to a single CPU,
# kill background daemons, disable frequency scaling:
taskset -c 1 sh -c '
    DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_verify
' 2>results/verify-submission.log
```

Exit codes:
- `0` — no leakage evidence at the configured budget
- `2` — leakage detected (t-statistic above dudect threshold)
- other — harness setup failure (look at stderr)

## CI integration

`scripts/check-high-assurance.sh` builds + runs the smoke test
automatically when `dudect/src/dudect.h` is present. The script
exits 0 either way:

- dudect not fetched → reports `[skip]` with install instructions
- harness builds but reports no leakage → `[ok]`
- harness reports leakage → `[LEAK]` (results pinned for review)
- harness build fails → `[info]` (mid-refactor, expected during
  ongoing development; the pulsarm package may not compile under
  cgo at every commit)

## Submission run

NIST evaluates constant-time at the submission deadline. The
submission-grade run requires:
- ~10^9 samples (configure via `DUDECT_SAMPLES` × `DUDECT_MAX_BATCHES`)
- Quiet machine: no background processes, perf governor pinned
- CPU pinning (`taskset -c <cpu>` on Linux, `pthread_setaffinity_np`
  inside the harness on macOS)

Pin the results to `ct/dudect/results/{verify,combine}-submission.log`
on the `submission-2026-11-16` tag.

Pass criterion: no t-test statistic above 4.5σ (dudect calls this
`t_threshold_moderate=10` by default — we apply the stricter NIST 4.5σ
post-hoc when reading the logs).
