# IDA MCP Server

# Show available recipes
default:
    @just --list

# Build debug binary
build:
    cargo build

# Build release binary
# KACHE_DISABLED=1: kache 0.13.0 restore-time mtime bugs can leave a stale
# binary while reporting success (kunobi-ninja/kache#677/#680/#682, fixed
# upstream 2026-08-08). Release artifacts bypass the cache until a fixed
# kache release ships; day-to-day debug builds keep it for disk savings.
release:
    KACHE_DISABLED=1 cargo build --release

# Build release binary linked against a specific IDA version (local testing, no publish)
release-against ida_version="9.4":
    KACHE_DISABLED=1 IDADIR="/Applications/IDA Professional {{ ida_version }}.app/Contents/MacOS" cargo build --release

# Sequential supervisor stdio session test. Opens fixtures/mini.i64.
# The root manifest is the IDA 9.4 build; override the path with SERVER_BIN.
test: build
    cd e2e && SERVER_BIN="${SERVER_BIN:-../target/debug/ida-headless-mcp}" RUST_LOG=ida_mcp=trace just test

# Verify the advertised catalog and resources without opening a database (no IDA license needed).
test-supervisor-catalog: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp just test-supervisor-catalog

# Run the multi-session supervisor HTTP integration test (79 safe / 80 unsafe tools).
test-supervisor-http: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-supervisor-http

# Exercise the tool surface, kill one worker, and verify isolation plus recovery.
test-supervisor-http-recovery: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-supervisor-http-recovery

# Verify that a licensed Hex-Rays installation can decompile a known function.
test-decompile: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-decompile

# Run HTTP integration test (debug)
test-http: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-http

# Run HTTP close-ownership recovery test (issue #19, PRs #18 / #21)
test-http-recovery: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-http-recovery

# Run legacy-session cancel-on-disconnect test (single-worker HTTP)
test-session-cancel: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-session-cancel

# Run HTTP startup-failure test (no IDA license or fixture required)
test-http-startup: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp just test-http-startup

# Run HTTP worker-pool concurrency test (debug)
test-pool: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-pool

# Run HTTP worker-pool crash-containment test (debug)
test-pool-crash: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-pool-crash

# Run HTTP worker-pool exhaustion test (debug)
test-pool-exhaustion: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-pool-exhaustion

# Run HTTP worker-pool failed-second-open lease preservation test (debug)
test-pool-second-open: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-pool-second-open

# Run HTTP worker-pool abandoned-client cleanup test (debug)
test-pool-disconnect: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-pool-disconnect

# Run HTTP worker-pool session-manager disconnect wiring test (debug, no IDA open)
test-pool-manager-disconnect: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-pool-manager-disconnect

# Run IDAPython script integration test (debug)
test-script: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-script

# Bootstrap deterministic .i64 fixture used by script/observability tests
test-bootstrap: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-bootstrap

# Run foreground observability integration test (debug)
test-observability: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-observability

# Run open_idb auto-background elicitation integration test (debug)
test-elicitation: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-elicitation

# Verify MCP 2026 discover/stateless lifecycle and the pooled legacy boundary.
test-modern: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-modern

# Run open_idb rebuild semantics test (raw reuse vs rebuild=true overwrite)
test-rebuild-idb: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-rebuild-idb

# Run dyld_shared_cache integration test (requires mounted iOS DMG; default path is /tmp/ios_sys_mount/...)
test-dsc dsc_path="": build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-dsc {{ if dsc_path != "" { dsc_path } else { "" } }}

# Verify that license validation succeeds during preflight or database open
test-license: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=info just test-license

# Run crash-guard integration test (triggers SIGSEGV, verifies server survives)
test-crash-guard: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-crash-guard

# Run callees-indirect regression test (PR #20: bundle-id naming + indirect-call operand filter)
test-callees-indirect: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-callees-indirect

# Measure the tools/list payload size (per-tool char ranking + descriptions/schemas split)
measure-tools: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp just measure-tools

# Verify server-side tool filtering (--toolsets / --tools / --exclude-tools / --read-only + env mirrors)
test-tool-filter: build
    cd e2e && SERVER_BIN=../target/debug/ida-headless-mcp RUST_LOG=ida_mcp=trace just test-tool-filter

# Run cargo unit tests
cargo-test:
    RUST_BACKTRACE=1 cargo test

# Reformat the tree in place.
fmt:
    cargo fmt --all

# Fail if the tree is not formatted. This is what CI runs; `fmt` rewrites and
# therefore can never fail, which makes it the wrong thing to gate on.
fmt-check:
    cargo fmt --all --check

# Run clippy over all three dependency tables.
#
# The three manifests share one source tree but cannot share a Cargo.lock: each
# idalib revision declares `links = "idalib"`, so only one can be in the graph.
# Drift between them is invisible until someone builds the other two, and it is
# not confined to the manifests — identical manifests can still resolve
# different transitive versions into their separate locks. This is the gate that
# notices either kind.
lint:
    cargo clippy --all-targets -- -D warnings
    cargo clippy --manifest-path sdk/ida-92/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path sdk/ida-93/Cargo.toml --all-targets -- -D warnings

# The full gate, identical to CI's verify job. Run this before pushing.
check: fmt-check lint cargo-test

# Clean build artifacts
clean:
    cargo clean

# Pushing the tag is the release: `.github/workflows/build.yml` builds every
# IDA minor on every platform for `refs/tags/v*` and attaches the archives plus
# checksums.txt to a GitHub Release. There is no other distribution channel.

# Bump version, update Cargo.toml + Cargo.lock, commit, tag, and push
bump:
    #!/usr/bin/env bash
    set -euo pipefail
    TAG="$(svu patch)"
    VERSION="${TAG#v}"
    CURRENT="$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')"
    if [[ "$VERSION" == "$CURRENT" ]]; then
        echo "Cargo.toml already at ${VERSION}"
    else
        sed -i '' "s/^version = \"${CURRENT}\"/version = \"${VERSION}\"/" Cargo.toml
        cargo update -p ida-headless-mcp
        git add Cargo.toml Cargo.lock
        git commit -m "chore: release ${VERSION}"
    fi
    git tag -a "$TAG" -m "Release $TAG"
    git push && git push --tags
