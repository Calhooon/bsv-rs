#!/bin/bash
# Cargo's target runner for the nightly Mutants job (#577): every test binary
# cargo runs is exec'd under a virtual-memory ceiling, so a mutant whose loop
# allocates without bound aborts on a refused allocation (a failed test, the
# mutant caught) instead of exhausting the hosted runner. rustc and the build
# scripts are not run through it.
#
# A platform that refuses `ulimit -v` (macOS) gets a warning and the binary
# runs unbounded; the limit in force is what the marker records, so the job's
# proof step, which compares it with MUTANTS_TEST_VMEM_KB, fails on Linux if
# the ceiling did not apply. MUTANTS_CEILING_MARKER, when set, names the file
# the limit is written to before the exec; the mutants' run leaves it unset.
set -euo pipefail
ulimit -v "${MUTANTS_TEST_VMEM_KB:-4000000}" 2>/dev/null \
  || echo "test-runner-memory-ceiling: ulimit -v unsupported here; running unbounded" >&2
if [[ -n "${MUTANTS_CEILING_MARKER:-}" ]]; then
  ulimit -v > "$MUTANTS_CEILING_MARKER"
fi
exec "$@"
