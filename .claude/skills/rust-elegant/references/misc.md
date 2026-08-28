# 杂项规范

## 1. 穷尽性检查：禁止 `_ => {}` 兜底

### 为什么重要

Rust `match` 的穷尽性检查是**免费的静态分析**。新增枚举变体时，编译器会在所有 `match` 处报错，强制你处理新情况。用 `_ => {}` 兜底，等于主动关掉这个保护。

### 反模式

```rust
// ❌ 用通配符兜底，新增 HardDeprecated 变体时没有任何警告
match status {
    Status::Active => do_thing(),
    Status::Deprecated => warn(),
    _ => {}  // 静默吞掉了所有未来的新变体
}

// ❌ unreachable! 也不行，它只是运行时 panic，不是编译时检查
match status {
    Status::Active => do_thing(),
    Status::Deprecated => warn(),
    _ => unreachable!(),  // 新增变体后：运行时 panic，不是编译报错
}
```

### 正确做法

```rust
// ✅ 穷尽所有变体，新增变体时编译器强制提醒
match status {
    Status::Active => do_thing(),
    Status::Deprecated => warn(),
    Status::HardDeprecated => error_and_refuse(),
    // 忘记加新变体？编译报错，不会悄悄出 bug
}
```

**唯一合理使用 `_` 的场景：** 你明确知道不关心某些变体，并且那些变体的语义就是"不处理"，而且你能接受未来新增变体时默认也不处理。即便如此，加一行注释说明原因。

---

## 2. `_` 前缀陷阱：掩盖逻辑漏洞

### 问题描述

clippy 报 `unused variable` 警告时，正确的第一反应是**检查后续逻辑是否被漏写**，而不是加 `_` 前缀消警告。

```rust
// ❌ clippy 报 unused，于是加下划线，业务逻辑被悄悄吞掉
let user_status = db.check_status(user_id).await?;
let _user_status = db.check_status(user_id).await?; // 警告消了，但校验逻辑没了

// ✅ 正确做法：补全被遗漏的业务逻辑
let user_status = db.check_status(user_id).await?;
if user_status == UserStatus::Banned {
    return Err(Error::UserBanned);
}
```

**规则：** 只有当你能明确说出"这个值确实不需要被使用"时，才用 `_` 前缀。如果说不出来，那就是逻辑漏洞。

---

## 3. 无效分配：能零拷贝就不分配

### 反模式

```rust
// ❌ 函数只读字符串，却要求传入已分配的 String
fn log_event(name: String) {  // 调用方被迫分配
    println!("[EVENT] {name}");
}

// ❌ 热路径里无脑 to_string()
for item in &items {
    let key = item.category.to_string();  // 每次循环都分配
    map.insert(key, item);
}

// ❌ 不必要的 clone 传参
fn process(config: Config) {  // 移动语义，调用方 config 消失
    use_config(&config);
}
// 调用方：process(self.config.clone()); // 为了保留 config 而 clone
```

### 正确做法

```rust
// ✅ 借用切片，零分配
fn log_event(name: &str) { ... }
// 调用方可以传字面量、String 引用、任何字符串类型

// ✅ 直接用 &str 作为 key（如果 map 支持）或用 Cow 推迟分配
fn process(config: &Config) {  // 借用，不消耗
    use_config(config);
}

// ✅ Cow：能借用就借用，必须拥有时才分配
use std::borrow::Cow;
fn normalize(s: &str) -> Cow<str> {
    if s.contains(' ') {
        Cow::Owned(s.replace(' ', "_"))  // 需要修改时才分配
    } else {
        Cow::Borrowed(s)                 // 不需要修改时零拷贝
    }
}
```

### 分配决策速查

| 场景 | 用什么 |
|---|---|
| 函数参数，只读字符串 | `&str` |
| 函数参数，只读切片 | `&[T]` |
| 函数参数，只读路径 | `&Path` 或 `impl AsRef<Path>` |
| 返回值可能需要也可能不需要分配 | `Cow<str>` |
| 需要存储且生命周期不确定 | `String` / `Vec<T>`（拥有所有权） |
| 跨线程共享只读数据 | `Arc<str>` / `Arc<[T]>` |

---

## 4. 宏的正确使用场景

### 什么时候该用宏而不是函数

**用宏的信号：** 代码中出现了 3 次以上完全相同的结构性模式（不只是参数不同，而是结构相同），或者需要在编译时生成代码、需要变参、需要捕获 `stringify!` 等宏能力。

```rust
// ❌ 重复的 match arm，每加一个版本都要同时改三个地方
impl Display for Version {
    fn fmt(...) { match self { V1 => "1.0", V2 => "2.0", V3 => "3.0" } }
}
impl FromStr for Version {
    fn from_str(s: &str) { match s { "1.0" => V1, "2.0" => V2, "3.0" => V3, ... } }
}
fn cli_arg(v: Version) -> &str { match v { V1 => "v1", V2 => "v2", V3 => "v3" } }

// ✅ 宏：在一个地方定义所有版本的映射
macro_rules! define_versions {
    ($($variant:ident => $str:literal, $cli:literal);* $(;)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Version { $($variant),* }

        impl std::fmt::Display for Version {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(match self { $(Self::$variant => $str),* })
            }
        }
        impl std::str::FromStr for Version {
            type Err = crate::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($str => Ok(Self::$variant),)*
                    _ => Err(crate::Error::UnknownVersion(s.to_string())),
                }
            }
        }
    }
}

define_versions! {
    V1 => "1.0", "v1";
    V2 => "2.0", "v2";
    V3 => "3.0", "v3";
}
// 新增版本：只改这一处
```

### 过程宏 vs 声明宏

- **声明宏** (`macro_rules!`)：用于重复模式、语法扩展，在当前 crate 定义即可
- **过程宏** (`#[derive(...)]`, `#[proc_macro]`)：用于复杂的代码生成，需要独立 crate，优先用已有的（`serde`, `thiserror`, `derive_more`）

### 不该用宏的场景

- 只是想少写几个参数 → 用 Builder 或默认值
- 只是想重用逻辑 → 用函数或 trait
- 宏会让调试变难，IDE 支持变差，报错信息变晦涩

---

## 5. 依赖管理：避免版本幻觉

### 反模式

```rust
// ❌ 凭记忆写版本，可能是两年前的旧版本
[dependencies]
tokio = "0.2"          # 现在是 1.x，API 完全不同
serde = { version = "1.0.100", features = ["derive"] }  # 不必要的精确版本

// ❌ 捏造不存在的方法
use tokio::fs::read_to_string;  // 这个方法的签名记错了
stream.next().await.unwrap()    // Stream API 在不同版本有变化
```

### 正确做法

```rust
// ✅ 用 cargo add 获取最新稳定版，不要手写版本号
// $ cargo add tokio --features full
// $ cargo add serde --features derive

// ✅ Workspace 统一管理版本
[workspace.dependencies]
tokio = { version = "1", features = ["full"] }  # 主版本号，自动跟踪 minor 更新

// ✅ 不确定 API → 查文档，不猜
// docs.rs/<crate-name> 是权威来源
```

### 对 AI 生成代码的警告

AI 的训练数据有时间截止，可能混用不同年份的 API：
- `tokio 0.x` 和 `tokio 1.x` 的 API 不兼容
- `actix-web 3.x` 和 `4.x` 有重大变化
- `hyper 0.x` 和 `1.x` 完全重写

**原则：生成代码后，对所有外部 crate 的方法调用，验证一遍它们在当前使用版本中确实存在。**
