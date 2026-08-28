# Building from source

## Prerequisites

- IDA Pro 9.2, 9.3, or 9.4 with a valid license
- Rust — pinned by `rust-toolchain.toml`; rustup installs it on first use.
  `Cargo.toml`'s 1.95 floor comes from vibrev-kit and is not separately tested,
  because the pin means nothing ever builds on it.
- LLVM/Clang for the C++ bindings
- The IDA SDK or a local IDA installation matching the selected feature

Release archives never contain IDA, the SDK, or IDA runtime libraries.

## Select one IDA minor

Each IDA minor has an independent Cargo manifest and lockfile because Cargo
forbids resolving multiple crates that declare the same native
`links = "idalib"` value. All manifests compile the same Rust source tree.

```bash
# IDA 9.4 (default)
IDADIR=/path/to/ida-9.4 cargo build --release

# IDA 9.3
IDADIR=/path/to/ida-9.3 cargo build --release \
  --manifest-path sdk/ida-93/Cargo.toml

# IDA 9.2
IDADIR=/path/to/ida-9.2 cargo build --release \
  --manifest-path sdk/ida-92/Cargo.toml
```

Each manifest enables exactly one matching SDK feature. The executable also
rejects a mismatched IDA runtime before opening a database — a build for one
minor cannot run against another once either side is 9.4, because `idalib`
reconstructs IDA-internal layouts by hand and 9.4 moved one of them.

### 9.2 and 9.3 need an extra linker flag

```bash
RUSTFLAGS="-C link-arg=-Wl,--allow-multiple-definition" \
  IDADIR=/path/to/ida-9.2 cargo build --release \
  --manifest-path sdk/ida-92/Cargo.toml
```

Their `idalib-sys` defines its C++ wrappers as non-`inline` free functions in
headers, so every translation unit that includes them emits its own strong
definition and the linker refuses — 244 symbols, five copies each. Upstream
made all of them `inline` for 9.4, which is why the default build needs no flag
and why 9.4 is the default.

## Platform setup

On Linux, set `IDADIR` to the installation containing `libida.so` and
`libidalib.so`. On macOS, use the application's `Contents/MacOS` directory. On
Windows, set `IDADIR` and add the same directory to `PATH` so `ida.dll` and
`idalib.dll` are discoverable.

Examples:

```text
/home/user/ida-pro-9.2
/Applications/IDA Professional 9.3.app/Contents/MacOS
C:\Program Files\IDA Professional 9.4
```

For SDK-only CI builds, set `IDASDKDIR`. Runtime tests still require a matching
licensed installation on the same platform and architecture.

## Output and run modes

The 9.4 binary is `target/release/ida-headless-mcp`; 9.2 and 9.3 builds are
under `sdk/ida-92/target/release` and `sdk/ida-93/target/release`
respectively. Windows adds the `.exe` suffix.

```bash
# Stdio supervisor
./target/release/ida-headless-mcp

# Streamable HTTP supervisor
./target/release/ida-headless-mcp serve-http --bind 127.0.0.1:8745

# Direct IDA probe
./target/release/ida-headless-mcp probe --path /path/to/binary --list 10
```

## CI and release matrix

CI compiles every IDA minor on Linux x86-64, macOS arm64, and Windows x86-64.
Tagged builds publish nine SDK-specific archives with checksums. Archives
contain only the executable, project documentation, and licenses; select the
archive whose IDA minor matches the installed runtime.

That GitHub Release is the entire distribution surface. There is no Homebrew
tap, Scoop bucket, snap, or Nix package to update after a tag, and no
publishing step outside `.github/workflows/build.yml`. `just bump` writes the
version, tags, and pushes; the tag push is what produces the release.

Release archives are named `ida-headless-mcp_${VERSION}_...` (product version
from `Cargo.toml`, currently `0.1.0`). That crate version is not an IDA
version: the IDA line lives in `COMPILED_IDA_VERSION`, and tags are
`v${product version}` (for example `v0.1.0`), not `v9.4.x`.

The SDK-stub builds validate compilation and linking only. Runtime and
differential tests still require licensed IDA installations and therefore run
in the private release-validation environment rather than public CI.
