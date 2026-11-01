#!/bin/bash
# Cargo's target runner for the nightly Mutants job (#577): every test binary
# cargo runs is exec'd under a virtual-memory ceiling, so a mutant whose loop
# allocates without bound aborts on a refused allocation (a failed test, the
# mutant caught) instead of exhausting the hosted runner. rustc and the build
# scripts are not run through it.
set -euo pipefail
ulimit -v "${MUTANTS_TEST_VMEM_KB:-12000000}"
exec "$@"
