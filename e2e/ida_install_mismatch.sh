#!/usr/bin/env bash
# A binary built for one IDA and pointed at another must refuse to start.
#
# It used to run. `build.rs` bakes several IDA install directories into RUNPATH,
# so the core library comes from whichever of them exists while IDA reads its
# plugins, processor modules and loaders from $IDADIR. Set $IDADIR to a
# different release and both halves resolve happily, to different installs — no
# version check fires, because the core library really is the right version.
# What followed was "Hex-Rays decompiler is not available", a SIGSEGV inside a
# processor module, and a dyld_shared_cache that would not open: three
# unrelated-looking failures, none of which named the cause.
#
# Needs no IDA license, database or fixture. The gate runs before IDA is
# initialized — that is the whole point of it — so a directory that is merely
# *not* the install directory is enough to trip it.
set -euo pipefail

BIN="${MCP_BIN:-${SERVER_BIN:-../target/release/ida-headless-mcp}}"

if [[ ! -x "$BIN" ]]; then
  echo "missing server binary: $BIN" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
# An existing directory that is definitely not an IDA install. `canonicalize`
# resolves symlinks before comparing, so a link back to the real install would
# compare equal and prove nothing.
wrong_dir="$tmpdir/not-an-ida-install"
mkdir -p "$wrong_dir"

cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT INT TERM

fail() {
  echo "❌ $1" >&2
  shift
  for extra in "$@"; do
    echo "$extra" >&2
  done
  exit 1
}

# run_mismatched <log> <args...> -> echoes the exit status.
run_mismatched() {
  local log="$1"
  shift
  local rc=0
  IDADIR="$wrong_dir" "$BIN" "$@" </dev/null >"$log" 2>&1 || rc=$?
  echo "$rc"
}

# --- The gate has to hold on every entry point that loads IDA. `worker` defers
# initialization to its first tool call and `serve` never initializes IDA in its
# own process at all, so neither would report a mixed install on its own.
for command in "worker" "serve --mode stdio"; do
  log="$tmpdir/$(echo "$command" | tr ' -' '__').log"
  # shellcheck disable=SC2086 # deliberate word splitting: the flags are the args
  rc="$(run_mismatched "$log" $command)"

  [[ "$rc" != "0" ]] ||
    fail "\`$command\` started against a mixed IDA installation" "$(cat "$log")"
  grep -Fq "IDA installation mismatch" "$log" ||
    fail "\`$command\` refused without naming the reason" "$(cat "$log")"
  # Both directories, or the reader cannot act on it — which is the entire
  # complaint this test exists to prevent recurring.
  grep -Fq "$wrong_dir" "$log" ||
    fail "\`$command\` never named the resource directory it would have used" "$(cat "$log")"
  # `-e`, not a bare pattern: the flag name starts with `--`, which grep would
  # otherwise try to parse as one of its own options.
  grep -Fq -e "--allow-ida-mismatch" "$log" ||
    fail "\`$command\` refused without offering a way past it" "$(cat "$log")"
  # A refusal must happen before IDA is touched, or it has already taken a
  # licence to tell the caller it will not run.
  ! grep -Fq "Initializing IDA library" "$log" ||
    fail "\`$command\` initialized IDA before refusing" "$(cat "$log")"
  echo "   $command refused with exit $rc and named both directories"
done

# --- `skills` answers out of a manifest baked into the binary. Gating it would
# break the command in exactly the situation it exists for: an installer
# inspecting an engine it has just found on a machine whose IDA is wrong.
skills_log="$tmpdir/skills.log"
skills_rc="$(run_mismatched "$skills_log" skills list)"
[[ "$skills_rc" == "0" ]] ||
  fail "\`skills list\` was gated on an IDA it does not use" "$(cat "$skills_log")"
echo "   skills list still answered (exit $skills_rc)"

# --- The waiver has to be honoured, and has to keep the diagnosis in the log:
# the caller waived the refusal, not the explanation.
waiver_log="$tmpdir/waiver.log"
IDADIR="$wrong_dir" "$BIN" --allow-ida-mismatch worker </dev/null >"$waiver_log" 2>&1 || true
grep -Fq -e "Continuing because --allow-ida-mismatch" "$waiver_log" ||
  fail "--allow-ida-mismatch did not get past the gate" "$(cat "$waiver_log")"
grep -Fq "IDA installation mismatch" "$waiver_log" ||
  fail "--allow-ida-mismatch swallowed the diagnosis as well as the refusal" \
    "$(cat "$waiver_log")"
echo "   --allow-ida-mismatch continued and kept the diagnosis"

# --- Same decision, spelled as an environment variable, because that is how a
# child worker inherits it from the supervisor that spawned it.
env_log="$tmpdir/env.log"
IDADIR="$wrong_dir" IDA_MCP_ALLOW_IDA_MISMATCH=1 "$BIN" worker </dev/null >"$env_log" 2>&1 || true
grep -Fq "Continuing because" "$env_log" ||
  fail "IDA_MCP_ALLOW_IDA_MISMATCH=1 did not get past the gate" "$(cat "$env_log")"
echo "   IDA_MCP_ALLOW_IDA_MISMATCH=1 continued"

echo "✅ IDA install mismatch test passed"
