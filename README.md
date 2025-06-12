# Q-Seal 加密库

一个使用Rust实现的加密库，支持将字符串加密为公钥，并使用简短的种子密钥进行还原。提供传统加密和后量子加密两种实现。

## 功能特点

- 基于种子的确定性密钥生成
- 传统RSA加密实现
- 后量子Kyber加密实现（抵抗量子计算攻击）
- 简单易用的API

## 依赖要求

- Rust 1.70+
- 依赖库：
  - ring: 0.17.7
  - rand: 0.8.5
  - base64: 0.21.7
  - pqcrypto: 0.17.0
  - pqcrypto-kyber: 0.8.0
  - pqcrypto-traits: 0.3.5
  - serde: 1.0
  - serde_json: 1.0

## 快速开始

### 安装

将以下依赖添加到你的`Cargo.toml`文件：

```toml
[dependencies]
ring = "0.17.7"
rand = "0.8.5"
base64 = "0.21.7"
pqcrypto = "0.17.0"
pqcrypto-kyber = "0.8.0"
pqcrypto-traits = "0.3.5"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

### 使用示例

#### 传统加密 (RSA)

```rust
use q_seal::traditional;

// 从种子生成密钥对
let seed = "my_secret_seed_123";
let (public_key, private_key) = traditional::generate_keypair_with_seed(seed)?;

// 加密
let message = "这是一个需要加密的消息";
let encrypted = traditional::encrypt(message, &public_key)?;

// 解密
let decrypted = traditional::decrypt(&encrypted, &private_key)?;
assert_eq!(message, decrypted);
```

#### 后量子加密 (Kyber)

```rust
use q_seal::post_quantum;

// 从种子生成密钥对
let seed = "my_quantum_seed_456";
let (public_key, private_key) = post_quantum::generate_keypair_with_seed(seed)?;

// 加密
let message = "这是一个需要加密的消息";
let encrypted = post_quantum::encrypt(message, &public_key)?;

// 解密
let decrypted = post_quantum::decrypt(&encrypted, &private_key)?;
assert_eq!(message, decrypted);
```

## 注意事项

- 当前实现主要用于演示和学习目的
- 传统RSA实现为简化版，实际应用中需要使用完整的RSA实现
- 后量子加密使用了Kyber768算法，该算法为NIST后量子加密标准候选

## 安全警告

- 在生产环境中使用前，请确保进行全面的安全审查
- 考虑使用更强的加密参数和更安全的密钥管理机制
- 对于高安全性需求，建议结合其他安全措施 