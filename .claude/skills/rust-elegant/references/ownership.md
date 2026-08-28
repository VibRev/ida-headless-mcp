# 所有权设计规范

## 核心原则

**借用检查器报错时，第一反应不是"怎么绕过去"，而是"我的数据流设计有问题吗？"**

`.clone()` 和 `Arc<Mutex<T>>` 是工具，不是万能胶。用来逃避借用检查器的 clone/锁会掩盖真正的设计问题，并在性能敏感路径上造成严重损耗。

---

## 反模式：借用报错就 clone

```rust
// ❌ 借用检查器报错 → 无脑 clone
fn process(data: &mut Vec<Item>) {
    let snapshot = data.clone();  // "先 clone 一份就好了"
    for item in &snapshot {
        if item.needs_update() {
            data.push(item.updated()); // 现在可以编译了，但分配了不必要的内存
        }
    }
}

// ✅ 重新设计：先收集需要更新的，再一次性修改
fn process(data: &mut Vec<Item>) {
    let updates: Vec<Item> = data.iter()
        .filter(|item| item.needs_update())
        .map(|item| item.updated())
        .collect();
    data.extend(updates);
}
```

---

## 反模式：`Arc<Mutex<T>>` 满天飞

```rust
// ❌ 每个字段都套 Arc<Mutex<>>，性能极差，死锁风险高
struct AppState {
    users:   Arc<Mutex<HashMap<UserId, User>>>,
    config:  Arc<Mutex<Config>>,
    counter: Arc<Mutex<u64>>,
}

// ✅ 根据访问模式选择合适的原语
struct AppState {
    users:   Arc<RwLock<HashMap<UserId, User>>>,  // 读多写少 → RwLock
    config:  Arc<Config>,                          // 只读 → 不需要锁
    counter: Arc<AtomicU64>,                       // 单值计数 → Atomic
}
```

---

## 选择正确原语的决策树

```
数据需要跨线程共享？
  └─ 否 → 不需要 Arc，重新设计所有权或用 Rc
  └─ 是 → 需要可变访问吗？
           └─ 否（只读） → Arc<T>，不需要任何锁
           └─ 是 → 什么访问模式？
                    ├─ 读多写少 → Arc<RwLock<T>>
                    ├─ 单一计数/标志 → Arc<Atomic*>
                    ├─ 消息传递（生产者-消费者）→ channel (mpsc/broadcast)
                    └─ 真正需要共享可变状态 → Arc<Mutex<T>>（谨慎使用）
```

---

## 常见借用冲突的正确解法

### 问题一：同时持有不可变和可变引用

```rust
// ❌ 编译报错：不能同时借用
fn update_first(items: &mut Vec<String>) {
    let first = &items[0];           // 不可变借用
    items.push(first.clone());       // 可变借用 → 报错
}

// ✅ 解法：先用完不可变引用，再可变操作
fn update_first(items: &mut Vec<String>) {
    let first = items[0].clone();    // 克隆出来，释放不可变借用
    items.push(first);
}

// ✅ 或者：用索引而不是引用
fn update_first(items: &mut Vec<String>) {
    let new_item = items[0].clone();
    items.push(new_item);
}
```

### 问题二：结构体字段借用冲突

```rust
// ❌ 编译报错：借用了 self.a 又借用了 self.b
struct Foo { a: Vec<i32>, b: Vec<i32> }
impl Foo {
    fn process(&mut self) {
        for x in &self.a {          // 借用 self
            self.b.push(*x);        // 再次借用 self → 报错
        }
    }
}

// ✅ 解法：拆分借用，直接操作字段
impl Foo {
    fn process(&mut self) {
        let Foo { a, b } = self;    // 解构，分别借用独立字段
        for x in a.iter() {
            b.push(*x);
        }
    }
}
```

### 问题三：所有权在闭包中移动

```rust
// ❌ 同一个值被多个闭包捕获
let data = expensive_data();
let f1 = move || use_data(&data);   // data 被移入 f1
let f2 = move || use_data(&data);   // 报错：data 已被移走

// ✅ 解法：Arc 共享，每个闭包拿一个 Arc clone
let data = Arc::new(expensive_data());
let data1 = Arc::clone(&data);
let data2 = Arc::clone(&data);
let f1 = move || use_data(&data1);
let f2 = move || use_data(&data2);
```

---

## clone 是否合理的判断标准

- ✅ 合理：类型是 `Copy` 的（i32、bool 等），derive 了 Clone 且数据很小
- ✅ 合理：`Arc::clone()`，只增加引用计数，不复制数据
- ✅ 合理：原型阶段，先跑通再优化
- ❌ 不合理：大型集合（Vec、HashMap）在热路径上 clone
- ❌ 不合理：clone 的唯一目的是让借用检查器闭嘴，并没有真正需要两份数据
- ❌ 不合理：每次调用函数都 clone 一个 String，而函数其实只需要 `&str`
