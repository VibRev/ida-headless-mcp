# 类型设计规范

## 1. 枚举行为归位

### 反模式
```rust
// ❌ 行为流放到 utils.rs
pub fn parse_version(v: &str) -> Result<Version, Error> { ... }
pub fn version_to_string(v: Version) -> &'static str { ... }
pub fn require_selectable(v: Version) -> Result<(), Error> { ... }
```

### 正确做法：标准 trait + impl 块

```rust
// ✅ 行为全部归位到类型上
impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::V1 => "1.0",
            Self::V2 => "2.0",
        })
    }
}

impl std::str::FromStr for Version {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1.0" => Ok(Self::V1),
            "2.0" => Ok(Self::V2),
            _ => Err(Error::UnknownVersion(s.to_string())),
        }
    }
}

impl Version {
    pub const LATEST: Self = Self::V2;

    pub fn require_selectable(self) -> Result<(), Error> {
        match self.status() {
            Status::Active => Ok(()),
            Status::Deprecated => Err(Error::Deprecated(self)),
        }
    }
}
```

**调用方对比：**
```rust
// ❌ 之前
let v = parse_version(s)?;
require_selectable(v)?;
let s = version_to_string(v);

// ✅ 之后
let v: Version = s.parse()?;   // FromStr，标准 .parse()
v.require_selectable()?;        // 方法在类型上
let s = v.to_string();          // Display，免费获得
```

### 转换类型选择速查

| 场景 | 用哪个 trait |
|---|---|
| `&str / String → T`，可失败 | `impl FromStr for T`（启用 `.parse()`） |
| `OtherType → T`，可失败 | `impl TryFrom<OtherType> for T` |
| `OtherType → T`，无损 | `impl From<OtherType> for T`（`Into` 自动获得） |
| `T → 显示字符串` | `impl Display for T`（`.to_string()` 自动获得） |
| 判等 / 用作 HashMap key | `#[derive(PartialEq, Eq, Hash)]` |
| 排序 | `#[derive(PartialOrd, Ord)]`（或手动实现并注释排序语义） |
| 零值 / builder 默认 | `#[derive(Default)]` 或手动 `impl Default` |

---

## 2. Trait 抽象替代 C 式传参

### 反模式
```rust
// ❌ 写死具体类型，无法测试，无法扩展
pub fn send_alert(
    smtp_host: &str,
    smtp_port: u16,
    recipient: String,
    subject: String,
    body: String,
) -> Result<(), Error> { ... }
```

### 修法一：对"能力"抽象

```rust
// ✅ 抽象出能力，而不是具体实现
pub trait Notifier: Send + Sync {
    fn notify(&self, recipient: &str, subject: &str, body: &str) -> Result<(), Error>;
}

pub struct SmtpNotifier { host: String, port: u16 }
impl Notifier for SmtpNotifier { ... }

pub struct StubNotifier(std::sync::Mutex<Vec<String>>); // 测试用
impl Notifier for StubNotifier { ... }

// 调用方只依赖 trait，随时可换实现
pub fn alert(notifier: &dyn Notifier, recipient: &str) -> Result<(), Error> {
    notifier.notify(recipient, "Alert", "Something happened")
}
```

### 修法二：参数 ≥ 4 个用 Builder

```rust
// ❌ 布尔参数地狱，调用方看不懂
fn create_pipeline(url: &str, workers: usize, timeout_ms: u64, retry: u32, cache: bool) -> Pipeline

// ✅ Builder：有默认值，自文档化
#[derive(Default)]
pub struct PipelineConfig {
    pub db_url:     String,
    pub workers:    usize,       // 默认：num_cpus
    pub timeout:    Duration,    // 默认：30s
    pub retry:      u32,         // 默认：3
    pub cache:      bool,
}

impl PipelineConfig {
    pub fn build(self) -> Result<Pipeline, Error> { ... }
}

// 调用方只写非默认的字段
let pipeline = PipelineConfig {
    db_url: env::var("DB_URL")?,
    workers: 8,
    ..Default::default()
}.build()?;
```

### 修法三：Newtype 携带语义

```rust
// ❌ 编译器无法区分这两个 u16，运行时才炸
fn connect(host: &str, port: u16, timeout_ms: u16) -> ...

// ✅ 类型系统在编译时防止参数顺序搞错
pub struct Port(u16);
pub struct TimeoutMs(u16);

impl Port {
    pub fn new(n: u16) -> Result<Self, Error> {
        (n != 0).then_some(Self(n)).ok_or(Error::InvalidPort)
    }
}

fn connect(host: &str, port: Port, timeout: TimeoutMs) -> ...
```

---

## 3. `&str` 和 `&[T]` 而不是 `&String` 和 `&Vec<T>`

### 反模式
```rust
// ❌ Rust 新手标志：&String 极大限制复用性
fn process(text: &String, items: &Vec<i32>) -> ...

// 调用方被迫：
process(&"hello".to_string(), &vec![1,2,3]); // 无意义的堆分配
```

### 正确做法
```rust
// ✅ 利用 Deref 强制转换，接受任何字符串/切片
fn process(text: &str, items: &[i32]) -> ...

// 调用方可以传：
process("hello", &[1, 2, 3]);               // 字面量，零分配
process(&owned_string, &owned_vec);          // 已有 String/Vec 也可以
process(arc_str.as_str(), slice);            // 任何东西都行
```

### 函数参数 impl Trait 速查

| 不要写 | 改写成 |
|---|---|
| `&String` | `&str` |
| `&Vec<T>` | `&[T]` |
| `String`（只读） | `impl AsRef<str>` 或 `&str` |
| `Vec<T>`（消费） | `impl IntoIterator<Item = T>` |
| `PathBuf` | `impl AsRef<Path>` 或 `&Path` |
| `Box<dyn Fn(...)>` | `impl Fn(...)` |
