# ida-headless-mcp 执行清单

> 本仓库的当前工作。**只写还没做完的。** 做完的东西活在代码和 git log 里，不在这里。
>
> 最后一次整理：2026-08-28。

---

## 现状

完整 MCP server + supervisor + 宏派生 CLI。默认命令是 supervisor（多数据库会话），`worker` 是单库的另一个面。

| 面 | tools | title / annotations / outputSchema |
|---|---|---|
| native / worker | **85** | 齐 |
| supervisor 安全面 | **85** | 齐 |
| `--unsafe` | **86** | 齐 |

数字的唯一真相是 `tests/snapshots/tool-surface.json`，由 `tests/tool_surface.rs` 强制。**任何地方要引用工具数就去读它，不要再抄一份**——抄出来的那份迟早会漂。

分发只有 GitHub Release 一条：打 tag → 三平台 × 三 SDK = 九份归档 + `checksums.txt`。没有 Homebrew tap / Scoop bucket / snap / nur。

---

## P0 —— 推之前必须解决

### 1. ~~`VibRev/vibrev` 是私有仓库，CI 取不到依赖~~ 已解决

三个 vibrev crate 是 git 依赖（`branch = "main"`）。仓库私有时 `actions/checkout` 的 `GITHUB_TOKEN` 只对当前仓库有效，CI 会死在**认证**上。

当时记的是「vibrev 后续转 public，届时零改动即可通过」。**它已经转 public 了**（`gh repo view VibRev/vibrev` 报 `isPrivate: false`，匿名 `git ls-remote` 能取到），所以这条不再需要任何动作。

实际影响不只是「不红了」：**CI 从此是一道真门禁**。在此之前它取不到依赖，任何本地改坏的东西 CI 都发现不了。

### 2. 六个 HTTP e2e 脚本调的是 worker 面的工具名

HTTP 传输只提供 **supervisor 面**（`idb_open` / `idb_close`，参数 `input_path`）。这些脚本调的是 **worker 面**的 `open_idb` / `close_idb`（参数 `path`），那两个工具在 supervisor 面根本不存在——snapshot 可查。

| 脚本 | recipe |
|---|---|
| `http_integration.sh` | `just test-http` |
| `http_pool.sh` | `just test-pool` · `test-pool-crash` |
| `http_script_integration.sh` | `just test-script` |
| `http_observability.sh` | `just test-observability` |
| `http_session_cancel.sh` | `just test-session-cancel` |
| `http_bootstrap.sh` | `just test-bootstrap` |

**产品没坏，是测试没跟上**：走 supervisor 名字的 `test-supervisor-http` 是通过的。这些脚本写于 `serve-http`（现已并入 `serve --mode http`）还在进程内提供 native 面的年代，那条拓扑已经删除。

`modern_protocol.sh` 同源：它等的启动横幅是 `"MCP HTTP server listening on"` / `"MCP pooled HTTP server listening on"`，而现在只打 `"MCP supervisor listening on"`；它还断言 `tools/list` 里有 `open_idb`。

> **一条被撤回的记录。** 这里一度写着「`--allow-origin` 的语义从 Origin 变成了 Host」并定为 P0 破坏性变更。**那是错的，测量方法有问题**：HTTP 传输有 `--allow-origin`（Origin 白名单，默认 `http://localhost,http://127.0.0.1`）和 `--allow-host`（额外 Host 头）两个独立的 flag，我把前者的名字和后者的说明看串了，那次「400」是自己 curl 参数写坏造成的。重测：带 `Origin: http://localhost` 是 **200**。`commit 7eed627` 的信息里留有这个错误说法。

### 3. Origin 校验已移除

按仓库所有者的决定，Origin 不再校验；Host 仍可通过 `--allow-host` 显式启用。实测敌意 Origin 在有效 token 下可通过，敌意 Host 仍按 Host 策略返回 403，无 token → 401。

Origin 校验代码已从 `vibrev-kit` 移除，两个引擎均同步到同一版本。

理由记在这里免得后人当成疏忽：这两个检查防的是 DNS 重绑定（浏览器里的页面把自己控制的域名解析到 127.0.0.1 来打本地监听）。**真正挡住它的是无条件的 bearer token**——那个页面读不到 token 文件。而常开的 Host 校验会误伤反向代理和容器 DNS 名。

---

### 4. CI 编译测试但跑不了它们

`verify` job 跑的是 `cargo test --locked --no-run`。原因不是偷懒：单元测试不开数据库，但它们所在的二进制链了 `libida`/`libidalib`，loader 在任何测试开始前就要解析这两个库。runner 上没有 IDA，链接时用的是 idalib SDK submodule 自带的 stub——那些 stub 只为满足链接器而存在，**把 loader 指向它们，测试进程在第一条测试之前就 SIGSEGV**（实测过）。`--no-default-features` 也不是出路，`build.rs` 要求必须选中一个 SDK feature。

所以 CI 回答的是「每个 target 在这个平台上编不编得过」——三个 runner 存在的意义正是这个问题——而那 301 条断言在有 IDA 的地方跑（`just check`，推送前）。

**这是一处真实的门禁削弱**：CI 抓不到测试回归。要补上得让 crate 支持一种不链 idalib 的构建模式（把 IDA 那层 cfg 掉），纯逻辑测试就能在任何机器上跑。那是一件独立的活。

> 参照：2026-08-17 那次 CI 是绿的，`cargo test --locked` 跑出 230 条通过——**当时默认 SDK 是 9.2**。换成 9.4 之后测试二进制才开始在加载期硬依赖 `libida.so`。

---

## P1 —— 已知缺口

| 项 | 状态 |
|---|---|
| supervisor 面没有 tasks 扩展 | worker 面有 `.enable_tasks()` + `TaskHost` 实现，supervisor 两样都没有。**它没有说谎**（没宣告未实现的能力），但 supervisor 是默认命令，所以 `open_dsc` 这类后台任务在默认面上无法用 `tasks/get` 轮询。补它等于给 supervisor 实现 `TaskHost` 并转发到正确的子 worker——是一个特性，不是修 bug |
| `test-crash-guard` / `test-callees-indirect` 未定性 | 前者报 "open_idb did not return a session_id"（疑似用错了面的工具名：supervisor 是 `idb_open`+`input_path`，worker 是 `open_idb`+`path`）；后者报 "callees missing direct_callee"（可能要重新编 `indirect.c` 夹具）。**都还没查** |
| Windows / macOS 一次都没验证过 | `verify` job 的三平台矩阵已经写好，但 CI 从 8-17 起就没跑过（见 P0-1）。孤儿防护、pipe EOF、文件锁在非 Linux 上仍然零证据 |
| `decompile` 路径未验证 | 本机无 Hex-Rays 授权（`IDA error: license not available (HEXX64)`）。这是授权事实不是缺陷，但意味着反编译面没有实测过 |
| GitHub Release 从没走通 | releases 数为 0。发布链路（tag → 九份归档 → checksums）只在纸面上成立 |

---

## 停靠（不是取消）

| 项 | 解冻条件 |
|---|---|
| `find_insns` / `find_insn_operands` 的响应改成类型 | 这两个是 worker 侧唯一返回裸 `serde_json::Value` 的读工具，所以 `assert_mirrors`（响应类型与 worker 类型逐字段对照）管不到它们——曾经出现过 schema 声明 5 个字段而 handler 发 8 个。补齐过一次，但**保不住**：下一个人往 `json!` 里加一个键，schema 照样不知道。要根治得像 `imports` 那样建 worker 类型并走四层 |
| Windows 真机 e2e | 需要一台装了 IDA 的 Windows。CI 给不了（它只有 SDK stub，跑不了真库） |
| `.cargo/config.toml` 的重复符号 flag 是全局的 | `--allow-multiple-definition` / `/FORCE:MULTIPLE` 只有 9.2/9.3 需要。Cargo 的 config 发现按**工作目录**向上走、不按 `--manifest-path`，而三份 manifest 都从仓库根调用，所以 9.4 也带着它——**同一个 ODR 违反回来时没人会发现**。解冻条件：找到一个既不改文档里的构建命令、又不给 CI 加一次全量重链的作法 |
| 第三方包管理器分发（brew / scoop / snap / nur） | 已删除。重开需要三样：法律核查结论、三个真实存在的 tap/bucket 仓库、一份能表达「一个 tag 下九份资产」的 manifest 生成器。三样都不具备时，重建的代价远低于维护一条指错人的链 |

---

## 不做

- `dbg_*` —— headless 没有调试器
- `--profile` / 工具数上限 —— 默认暴露全部可用工具
- `analyze_component.addrs` 保持 `Value` —— 它收名字或地址，不是纯 `AddressArg`。其余 36 个地址字段都换成具名类型了，这一处故意留下
- 5 个工具继续裸 `#[rmcp::tool]` —— 结构上不可迁，不要为迁而迁
- 全库 `func_profile` —— `list_funcs(sort_by=size)` + `func_profile(数组)` 两步等价，全库逐个 profile 在大库上不可接受

---

## 门禁

```bash
just check        # = fmt + lint + cargo-test，与 CI 的 verify job 同一套
```

拆开是：

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --manifest-path sdk/ida-92/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path sdk/ida-93/Cargo.toml --all-targets -- -D warnings
cargo test        # 301 + 8 + 13
```

**这四条必须一起跑。** 只跑 `cargo test` 会漏掉 clippy（CI 带 `-D warnings`，本地不带就是「本地全绿、推上去必红」），只跑根 manifest 会漏掉另外两份依赖表。

三份 manifest 共用一份源码但**不能共用 `Cargo.lock`**：每个 idalib 修订都声明 `links = "idalib"`，Cargo 不允许两个同时在依赖图里。所以拆是必须的——而拆开的代价就是它们会各自漂移，`lint` 跑三份是唯一便宜的止血。**注意漂移不只发生在 manifest 上**：三份 manifest 逐字相同时，lock 里的传递依赖版本仍然可以各走各的。

e2e 另算，需要 IDA：

```bash
just test                      # supervisor stdio 全链路，40 个工具
just test-supervisor-http      # 多会话 HTTP
just test-tool-filter          # 工具过滤（flag / env / 覆盖 / 拒绝未知）
just test-supervisor-catalog   # 不需要 license
just test-http-startup         # 不需要 license
```

---

## 实机注意事项

- `IDADIR` 必须是绝对路径，`~` 不展开
- 目标二进制放在可写目录里——旁边要建 `.imcp`
- supervisor 面 `idb_open` 收 `input_path`，worker 面 `open_idb` 收 `path`。**两个面的开库工具不同名也不同参**
- 跑单个 e2e 脚本时设 `MCP_BIN` 一个变量就够（脚本会依次回退到 `MCP_STDIO_BIN` / `MCP_HTTP_BIN` / `SERVER_BIN`，默认 `../target/release/`）
- 不同 IDA minor 的二进制不能互换。9.4 起 ABI 不兼容，用错会死在 IDA 自己的 init 里
