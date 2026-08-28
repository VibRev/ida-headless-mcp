---
name: rust-elegant
description: >
  Rust 优雅开发规范，必须在以下场景触发：为 Rust 项目写代码、review Rust 代码、
  设计 Rust 项目结构、处理 Rust 错误类型时。覆盖注释规范、枚举设计、trait 抽象、
  项目结构、错误处理、所有权、迭代器、宏、内存分配、match 穷尽性等所有 Rust
  惯用法。只要任务涉及写或修改 Rust 代码，必须读取此 skill。
---

# Rust 优雅开发规范

**核心原则：写出来的代码要让有经验的 Rust 工程师看了不难受。能跑不是标准，惯用、可维护、高性能才是标准。**

---

## 快速诊断：看到这些立刻停下来

| 看到这个 | 说明踩了反模式 | 去读 |
|---|---|---|
| `fn parse_xxx` / `fn xxx_to_string` 作为自由函数 | 枚举行为被流放 | [type-design.md](references/type-design.md) |
| `utils.rs` / `helpers.rs` / `ext.rs` 里有枚举相关函数 | 同上 | [type-design.md](references/type-design.md) |
| 函数参数列表超过 3 个，或含 `bool` 参数 | C 式传参 | [type-design.md](references/type-design.md) |
| `fn foo(x: &String)` / `fn foo(x: &Vec<T>)` | 过度具体化 | [type-design.md](references/type-design.md) |
| `.unwrap()` 或 `Box<dyn std::error::Error>` | 错误处理走极端 | [error-handling.md](references/error-handling.md) |
| `Arc<Mutex<T>>` 满天飞，或借用报错就 `.clone()` | 所有权逃避 | [ownership.md](references/ownership.md) |
| `let mut result = Vec::new(); for ... { result.push(...) }` | 拒绝迭代器 | [iterators.md](references/iterators.md) |
| `match opt { Some(x) => ..., None => ... }` 多层嵌套 | Option/Result 组合子盲区 | [iterators.md](references/iterators.md) |
| `_ => {}` 或 `_ => unreachable!()` 兜底 enum match | 放弃穷尽性检查 | [misc.md](references/misc.md) |
| `let _foo = ...` 压掉 unused warning | 掩盖逻辑漏洞 | [misc.md](references/misc.md) |
| 不必要的 `.to_string()` / `.clone()` 在函数签名或热路径 | 无效分配 | [misc.md](references/misc.md) |
| 重复的模式匹配或样板代码超过 3 次 | 该用宏了 | [misc.md](references/misc.md) |
| 所有代码堆一个 `main.rs` 或 `lib.rs` | 缺少 Workspace 拆分 | [project-structure.md](references/project-structure.md) |
| `///` 写废话，或 `// ====` 横幅注释 | 违反注释规范 | [comments.md](references/comments.md) |
| 捏造或混用不同年份的 crate API | 依赖幻觉 | [misc.md](references/misc.md) |

---

## 写代码前的强制检查清单

在落笔前，依次问自己：

**1. 这个函数是某个类型的行为吗？**
- 是 → 写进 `impl T`，不要写成自由函数

**2. 涉及转换？**
- `&str/String → T` → `impl FromStr for T`（支持 `.parse()`）
- `T → 显示字符串` → `impl Display for T`
- 无损转换 → `impl From<A> for B`
- 有损转换 → `impl TryFrom<A> for B`

**3. 函数参数只需要某种"能力"，不需要具体类型？**
- → 定义 trait，参数用 `impl ThatTrait`

**4. 参数 ≥ 4 个，或含 bool/Option 参数？**
- → Builder pattern（`Config { ..Default::default() }.build()`）

**5. 参数是 `&String` 或 `&Vec<T>`？**
- → 改成 `&str` 或 `&[T]`

**6. 遇到借用检查器报错？**
- 先想：能不能改数据流或所有权结构？
- 不能再考虑：`Rc` / `Arc`（共享所有权）、`RefCell` / `Mutex`（内部可变性）
- 绝对不能：看到报错就无脑 `.clone()` 或套 `Arc<Mutex<T>>`

**7. 错误处理：**
- library crate → `thiserror` 定义具体错误枚举
- application / bin → `anyhow` 快速传播
- 任何地方 → 禁止 `.unwrap()`（测试除外），禁止 `Box<dyn Error>`

**8. match 一个枚举时：**
- 必须穷尽所有变体，不得用 `_ => {}` 或 `_ => unreachable!()` 兜底
- 编译器的穷尽性检查是免费的静态分析，不要白白丢掉

**9. 有 unused variable 警告？**
- 先问：后续处理逻辑是不是漏写了？
- 确认不需要再用 `_` 前缀或 `let _ =`
- 严禁用 `let _foo = ...` 掩盖真正遗漏的业务逻辑

**10. 要用外部 crate？**
- 用 `cargo add <crate>` 获取最新版，不要凭记忆写版本号
- 不确定某个方法/宏是否存在 → 查文档，不要猜

---

## 详细规范

各专题详细说明和 before/after 示例在 `references/` 目录：

- **[comments.md](references/comments.md)** — 注释规范（Why/Safety/Contract，禁止废话和横幅）
- **[type-design.md](references/type-design.md)** — 枚举设计、trait 抽象、Newtype、Builder、`&str` vs `&String`
- **[error-handling.md](references/error-handling.md)** — thiserror/anyhow 使用决策，禁止 `.unwrap()` 和 `Box<dyn Error>`
- **[ownership.md](references/ownership.md)** — 所有权设计，避免无脑 clone/锁
- **[iterators.md](references/iterators.md)** — Iterator 链式调用，Option/Result 组合子
- **[project-structure.md](references/project-structure.md)** — Workspace 拆分，crate 边界设计
- **[misc.md](references/misc.md)** — 宏、穷尽性检查、无效分配、依赖管理、`_` 前缀陷阱
