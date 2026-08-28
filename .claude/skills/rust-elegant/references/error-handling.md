# 错误处理规范

## 核心决策树

```
这是 library crate（被别人依赖的）？
  ├─ 是 → 用 thiserror 定义具体错误枚举，调用方可以 match
  └─ 否（bin / application）→ 用 anyhow，快速传播，专注业务逻辑

更准确的判断标准（来自 Luca Palmieri）：
  调用方需要根据不同错误做不同处理？
    ├─ 是 → thiserror 枚举，让调用方可以 match 变体
    └─ 否（只是上报/打日志）→ anyhow::Error 足够
```

---

## 反模式

```rust
// ❌ 1. unwrap 定时炸弹
let config = std::fs::read_to_string("config.toml").unwrap();
let port: u16 = env::var("PORT").unwrap().parse().unwrap();

// ❌ 2. Box<dyn Error> 摆烂，调用方无法区分错误类型
fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&text)?;
    Ok(cfg)
}

// ❌ 3. 手写 From 实现样板（有 thiserror 之后没必要）
impl std::fmt::Display for MyError { ... }
impl std::error::Error for MyError { ... }
impl From<std::io::Error> for MyError { ... }
```

---

## 正确做法

### Library crate：thiserror

```rust
// ✅ 具体枚举，调用方能 match
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found at {path}")]
    NotFound { path: PathBuf },

    #[error("invalid TOML: {0}")]
    ParseFailed(#[from] toml::de::Error),  // #[from] 自动生成 From impl

    #[error("missing required field: {field}")]
    MissingField { field: &'static str },
}

// 调用方可以精确处理
match load_config("config.toml") {
    Err(ConfigError::NotFound { path }) => use_defaults(),
    Err(ConfigError::ParseFailed(e)) => eprintln!("Bad config: {e}"),
    Err(e) => return Err(e),
    Ok(cfg) => cfg,
}
```

### Application / bin：anyhow

```rust
// ✅ 快速传播，专注业务，自动带 backtrace
use anyhow::{Context, Result};

fn main() -> Result<()> {
    let config = load_config("config.toml")
        .context("failed to load configuration")?;

    let port: u16 = std::env::var("PORT")
        .context("PORT env var not set")?
        .parse()
        .context("PORT must be a valid u16")?;

    run(config, port)
}
```

### 混用：thiserror 定义 + anyhow 传播

```rust
// ✅ 库暴露具体类型，应用层用 anyhow 包装
// 在 lib crate：
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("rate limit exceeded")]
    RateLimit,
    #[error("upstream error: {0}")]
    Upstream(#[from] reqwest::Error),
}

// 在 bin crate：
use anyhow::Result;

async fn fetch_data() -> Result<Data> {
    let resp = api_client.get(url).await?; // ApiError 自动转 anyhow::Error
    Ok(resp)
}
```

---

## `.unwrap()` 和 `.expect()` 使用准则

| 场景 | 怎么做 |
|---|---|
| 生产代码，可能失败 | `?` 传播错误，或 `.context("...")?` |
| 值"逻辑上不可能为 None/Err" | `.expect("说明为什么不可能")`，写清理由 |
| 单元测试 | `.unwrap()` 可以，测试 panic 就是 test fail |
| 初始化时的 panic（如正则编译） | `static REGEX: Lazy<Regex> = Lazy::new(|| Regex::new("...").unwrap())` 可以接受，加注释说明 |
| 任何生产路径 | 禁止裸 `.unwrap()` |

---

## `?` 操作符是标准，不是可选的

```rust
// ❌ 手写 match 传播错误，没有任何好处
let file = match File::open(path) {
    Ok(f) => f,
    Err(e) => return Err(e),
};

// ✅ ? 操作符，简洁，配合 From trait 自动类型转换
let file = File::open(path)?;
```
