# ida-headless-mcp

[English](README.md) | 简体中文

用 Rust 实现的多会话无头 [IDA Pro](https://hex-rays.com/ida-pro) MCP 服务器。

本项目派生自 [blacktop/ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs)，按明确的 supervisor / worker 拆分重写，会话模型借鉴自 [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)，但不再实现其工具契约。它不是上游 Homebrew / Scoop 包的即插即用替代品，也不是 Hex-Rays 官方产品。

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## 本项目多做了什么

- 一个 supervisor 进程负责 MCP 的 stdio 或 Streamable HTTP。
- 每个打开的数据库对应独立的 IDA worker 进程；崩溃只影响一个会话，不会拖垮服务器。
- 会话生命周期显式化：`idb_open`、`idb_list`、`idb_close`、`server_health`，以及全部需要 `database` 会话 ID 的分析工具。
- 默认 85 个工具，加 `--unsafe` 是 86 个，分为 12 个分类。
- 仅无头模式：调试器和 GUI 控制不进入公开接口。

详见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 和 [docs/MIGRATION.md](docs/MIGRATION.md)。

## 前置条件

- 已授权的 IDA Pro 9.2、9.3 或 9.4
- Rust（仅源码构建需要）—— 版本由 `rust-toolchain.toml` 钉住，rustup 会自动装。
  `Cargo.toml` 里声明的 1.95 下限来自 vibrev-kit，但真正生效的是那个 pin。
- 用于 C++ 绑定的 LLVM/Clang（仅源码构建需要）

发行构建从不附带 IDA、SDK 或 IDA 运行时库。你必须在同一平台和架构上已有授权的 IDA 安装。

## 安装

本项目不提供任何包管理器分发——没有 Homebrew tap，没有 Scoop bucket，也没有 snap。只有两条路：

1. **下载预编译产物。** 从 [Releases](https://github.com/fuqiuluo/ida-headless-mcp/releases) 下载，用 `checksums.txt` 校验，然后把可执行文件放到 `PATH` 上。
2. **从源码构建**（见下）——其他平台或架构只有这一条路。

产物命名为 `ida-headless-mcp_<版本>_ida-<IDA 小版本>_<系统>_<架构>`，Unix 是 `.tar.gz`，Windows 是 `.zip`。`<系统>` 取值为 `Linux`、`macOS` 或 `Windows`。每次发布覆盖三个 IDA 小版本（9.2、9.3、9.4）× 三种平台组合（`Linux_x86_64`、`macOS_arm64`、`Windows_x86_64`），共九个压缩包。每个包内除可执行文件外还带 `README.md`、`LICENSE` 和 `NOTICE`。

请选择与本机 IDA 小版本一致的那一个。二进制在打开数据库之前会检查已加载的 IDA 版本：只要任何一侧到了 9.4，小版本就必须精确匹配——因为 `idalib` 是手工还原 IDA 内部布局的，而 9.4 改动了其中之一。9.4 以下只比较大版本（IDA 9.3 把自己的产品版本报告成 9.0），但对齐小版本仍然是更稳妥的习惯。

## 构建

见 [docs/BUILDING.md](docs/BUILDING.md)。每个 IDA 小版本有各自的清单，只能选一个：

```bash
# IDA 9.4（默认）
IDADIR=/path/to/ida-9.4 cargo build --release

# IDA 9.3
IDADIR=/path/to/ida-9.3 cargo build --release \
  --manifest-path sdk/ida-93/Cargo.toml

# IDA 9.2
IDADIR=/path/to/ida-9.2 cargo build --release \
  --manifest-path sdk/ida-92/Cargo.toml
```

9.4 的二进制在 `target/release`；9.2 和 9.3 使用各自清单目录下的 `sdk/ida-*/target/release`。Windows 会加上 `.exe` 后缀。9.2 和 9.3 的构建还需要一个额外的链接器参数，见 [docs/BUILDING.md](docs/BUILDING.md)。

`just --list` 会列出仓库的构建与测试 recipe；哪些需要授权的 IDA 见 [docs/TESTING.md](docs/TESTING.md)。

## 平台设置

进程在运行时链接 IDA。如果安装不在默认位置，需要显式指向它：

| 平台 | 常见路径 | 运行时提示 |
|----------|--------------|--------------|
| Linux | `~/ida-pro-9.4` 或 `/opt/ida-pro-9.4` | `IDADIR` 或 `LD_LIBRARY_PATH` |
| macOS | `/Applications/IDA Professional 9.4.app/Contents/MacOS` | `IDADIR` 或 `DYLD_LIBRARY_PATH` |
| Windows | `C:\Program Files\IDA Professional 9.4` | 把 exe 放在 `ida.dll` 旁边，或设置 `IDADIR` 并把该目录加入 `PATH` |

```bash
# Linux / macOS
export IDADIR=/path/to/ida
./target/release/ida-headless-mcp
```

```powershell
# Windows
$env:IDADIR = "C:\Program Files\IDA Professional 9.4"
.\target\release\ida-headless-mcp.exe
```

## 配置 MCP 客户端

不带子命令直接运行，等价于 `serve`：一个 stdio supervisor。把二进制放到 `PATH` 上（或使用绝对路径）后：

### Claude Code

```bash
claude mcp add ida -- ida-headless-mcp
```

### Codex CLI

```bash
codex mcp add ida -- ida-headless-mcp
```

### Cursor

写入 `.cursor/mcp.json`：

```json
{
  "mcpServers": {
    "ida": {
      "command": "ida-headless-mcp",
      "env": {
        "IDADIR": "/path/to/ida"
      }
    }
  }
}
```

## 用法

supervisor 从 `idb_open` 返回一个不透明的会话 ID。之后每个分析工具都把该 ID 作为 `database` 传入，用完再关闭会话。

```
idb_open(input_path: "~/samples/malware")
idb_list()
list_funcs(database: "<session_id>", offset: 0, limit: 20)
find_string(database: "<session_id>", query: "libc")
disasm(database: "<session_id>", address: "0x100000f00")
xrefs_to(database: "<session_id>", address: "0x100000f00")
decompile(database: "<session_id>", address: "0x100000f00")
idb_close(database: "<session_id>")
```

几条能省一次往返的事实：

- `input_path` 可以是原始二进制（Mach-O/ELF/PE），也可以是已有的 `.i64`/`.idb`。同一个规范化路径第二次打开会复用已存在的会话，而不是再起一个 worker。
- 会话闲置 `idle_ttl_sec` 秒后被回收（默认 600）；传 `0` 关闭回收。
- `idb_open` 接受 `mode` 参数：`prefer_headless`（默认）、`force_headless` 和 `prefer_gui` 都会得到无头 worker；`force_gui` 返回稳定的不支持模式错误——本构建只支持无头。
- `--max-databases`（默认 4）限制 stdio supervisor 同时保活的 worker 进程数。
- `server_health` 不需要打开任何数据库就能报告 supervisor 状态。

从旧的 `ida-pro-mcp` 兼容工具名迁移？对照表见 [docs/MIGRATION.md](docs/MIGRATION.md)。

### Streamable HTTP

```bash
./target/release/ida-headless-mcp serve-http --bind 127.0.0.1:8765
```

与 stdio 不同，这条路径会开一个监听端口，因此**每个请求都必须带 bearer token**，没有关闭它的开关。token 存放在 `$VIBREV_HOME/token`，未设置该变量时是 `~/.vibrev/token`（权限 `0600`，首次使用时生成、之后长期复用）；`--token-file` 可以改位置。服务启动时会打印一段安全提示横幅和可直接粘贴的客户端配置片段：

```jsonc
"ida-headless-mcp": {
  "type": "http",
  "url": "http://127.0.0.1:8765/mcp",
  "headers": { "Authorization": "Bearer vbr_…" }
}
```

当 stderr 不是终端时，片段里的 token 会被省略，避免重定向的日志和 CI 输出泄露它；需要时用 `head -n1 ~/.vibrev/token` 读回。

这里控制子 worker 进程池大小的是 `--max-workers`（默认 4），不是 `--max-databases`。鉴权、Origin/Host 检查、会话保活以及其余进程池参数见 [docs/TRANSPORTS.md](docs/TRANSPORTS.md)。

### 内置 skill

二进制里带了一份 IDAPython 参考 skill（105 个文件，压缩进可执行文件），用来告诉模型这套工具底下的 `ida_*` API 长什么样。它在构建时从 `skills/` 打包进来，导出时逐字节还原：

```bash
ida-headless-mcp skills list
ida-headless-mcp skills export --dir ~/.claude/skills
```

这两条命令都不打开数据库，也不需要 IDA 授权——答案就烤在二进制里。`vibrev install ida` 会替你调用它们，并把结果放到 Claude Code 会读的位置，见 `vibrev skill --help`。只有 Claude Code 有 skill 机制，其他客户端拿到的就是纯粹的 MCP 服务器。

### 工具过滤

默认配置公开除 `run_script` 之外的全部工具；`run_script` 会在 worker 进程内执行任意 IDAPython，需要 `--unsafe`（或 `IDA_MCP_UNSAFE=true`）才会启用——这个开关也只管这一个工具。

想收窄接口则用：

- `--toolsets` 只保留指定分类：`core`、`functions`、`disassembly`、`decompile`、`xrefs`、`control_flow`、`memory`、`search`、`metadata`、`types`、`editing`、`scripting`。
- `--tools` 在 `--toolsets` 之上追加单个工具。
- `--exclude-tools` 排除工具；排除永远压过包含。
- `--read-only` 只保留声明了 `readOnlyHint` 的工具，因此它跟着目录走，不依赖手工维护的名单。

以上每个都有对应的环境变量（`IDA_MCP_TOOLSETS`、`IDA_MCP_TOOLS`、`IDA_MCP_EXCLUDE_TOOLS`、`IDA_MCP_READ_ONLY`）。

### Lumina

除非显式打开，否则不会自动查询 Lumina：

```bash
ida-headless-mcp --allow-lumina
```

等价环境变量是 `IDA_MCP_ALLOW_LUMINA=true`。本服务器使用隔离的 IDA 用户配置，不会改动平时 GUI 使用的配置。

## 已知限制

- **IDA 需要自备。** 这里的任何产物都不包含 IDA、它的 SDK 或运行时库，没有已授权的安装就跑不起来。
- **依赖反编译器的工具需要 Hex-Rays。** 没有反编译器授权时，worker 在预热阶段就会报 "Hex-Rays decompiler is not available"，`decompile`、`pseudocode_at`、`diff_before_after` 以及 `analyze_function` 里的伪代码部分都给不出结果；基于反汇编的功能不受影响。
- **预编译产物只覆盖三种平台组合**——Linux x86_64、macOS arm64、Windows x86_64。其余情况只能从源码构建。
- **一份二进制绑定一个 IDA 小版本。** 用 9.4 的构建去配非 9.4 的运行时（或者反过来），在打开任何数据库之前就会被拒绝。
- **仅无头。** 没有调试器接口，也没有 GUI 控制；`force_gui` 是错误，不是降级。
- **HTTP 始终需要鉴权。** 没有匿名模式，发不出 `Authorization` 头的客户端用不了这条传输。

## 文档

- [docs/TOOLS.md](docs/TOOLS.md) — worker 工具目录
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) — stdio 与 Streamable HTTP
- [docs/BUILDING.md](docs/BUILDING.md) — 从源码构建
- [docs/TESTING.md](docs/TESTING.md) — 运行测试
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — supervisor / worker 设计
- [docs/MIGRATION.md](docs/MIGRATION.md) — 旧 `ida-pro-mcp` 兼容工具名的迁移对照表

## 致谢

IDA worker、MCP 工具实现和构建胶水中的相当一部分来自 **blacktop** 的 [ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs)，MIT License。

多数据库会话模型（`idb_open` / `idb_list` / `idb_close` 以及每个分析工具上的 `database` 参数）借鉴自 **Duncan Ogilvie** 及贡献者的 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)，MIT License；本项目不再实现其工具契约，见 [docs/MIGRATION.md](docs/MIGRATION.md)。

IDA 绑定来自 [idalib](https://github.com/blacktop/idalib)（`MIT OR Apache-2.0`）。

完整声明见 [NOTICE](NOTICE)。

## 许可证

MIT。Copyright (c) 2026 **blacktop**。Copyright (c) 2026 **fuqiuluo** 与 ida-headless-mcp 贡献者。

见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。
