# q-seal

> 一个基于 Rust 的命令行工具与库，支持传统 RSA（RSA-2048）和后量子 Kyber（Kyber-768）加密/解密，并提供安全的私钥存储与管理。

## 功能特性

- 传统 RSA 加密/解密（OAEP(SHA256) 填充，RSA-2048）
- 后量子 Kyber 加密/解密（Kyber-768，结合 HKDF + AES-GCM）
- 私钥安全存储（Argon2id 派生 + AES-256-GCM 加密，JSON 序列化）
- 支持文本字符串或文件的加密/解密
- 交互式密码输入或命令行密码参数
- 生成 Shell 自动补全脚本（Bash、Zsh、Fish 等）
- 同时提供命令行工具与可编程库

## 目录

- [安装](#安装)
- [快速开始](#快速开始)
  - [命令行工具](#命令行工具)
  - [库使用示例](#库使用示例)
- [功能详解](#功能详解)
- [测试](#测试)
- [贡献](#贡献)
- [许可](#许可)

## 安装

### 环境要求

- Rust 1.70+ (建议使用最新稳定版)
- Cargo

### 构建与安装

克隆仓库并编译发布版：

```bash
git clone https://github.com/your_username/q-seal.git
cd q-seal
cargo build --release
```

可选地将二进制安装到本地 Cargo bin：

```bash
cargo install --path .
```

## 快速开始

### 命令行工具

基本用法：

```bash
q-seal <SUBCOMMAND> [OPTIONS]
```

查看全局帮助：

```bash
q-seal --help
```

各子命令帮助：

```bash
q-seal traditional --help
q-seal traditional encrypt --help
q-seal post-quantum --help
q-seal post-quantum decrypt --help
q-seal generate-completions --help
```

#### 示例：传统 RSA 加密/解密

- **加密文本并输出到默认文件**：

```bash
q-seal traditional encrypt --text "Hello, World!"
# 生成 rsa_key.json (默认密钥文件) 与 rsa_ciphertext.b64 (默认密文文件)
```

- **加密文件并自定义输出路径**：

```bash
q-seal traditional encrypt --in secret.txt --out cipher.b64 --key-out my_rsa_key.json
```

- **交互式加密私钥（提示输入密码）**：

```bash
q-seal traditional encrypt --text "Sensitive Data"
# 默认提示输入密码并将加密后的私钥保存到 rsa_key.json
```

- **不保存到文件，仅在终端显示结果**：

```bash
q-seal traditional encrypt --text "Quick Test" --no-file
```

- **解密密文**：

```bash
q-seal traditional decrypt --in cipher.b64 --key my_rsa_key.json --out decrypted.txt
```

- **使用命令行密码参数解密**：

```bash
q-seal traditional decrypt --text "<Base64密文>" --key rsa_key.json --password your_password
```

#### 示例：后量子 Kyber 加密/解密

```bash
# 加密
q-seal post-quantum encrypt --in data.bin --out kyber_cipher.b64 --key-out kyber_key.json

# 解密
q-seal post-quantum decrypt --in kyber_cipher.b64 --key kyber_key.json --out recovered.bin
```

#### 生成 Shell 自动补全脚本

```bash
# Bash:
q-seal generate-completions bash > q-seal.bash
# Zsh:
q-seal generate-completions zsh > _q-seal
```

### 库使用示例

如果希望在 Rust 项目中直接使用加密库：

```toml
[dependencies]
q-seal-core = { path = "core" }
``` 

```rust
use q_seal_core::{traditional, post_quantum, secure_key::SecureKeyContainer};
use rsa::rand_core::OsRng;
use secrecy::SecretString;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // RSA 示例
    let mut rng = OsRng;
    let (pub_rsa, priv_rsa) = traditional::generate_keypair(&mut rng)?;
    let ct_rsa = traditional::encrypt(b"Hello RSA", &pub_rsa, &mut rng)?;
    let pt_rsa = traditional::decrypt(&ct_rsa, &priv_rsa)?;
    println!("RSA 解密结果: {}", pt_rsa);

    // Kyber 示例
    let (pub_k, priv_k) = post_quantum::generate_keypair();
    let ct_k = post_quantum::encrypt(b"Hello Kyber", &pub_k, None, &mut rand::rng())?;
    let pt_k = post_quantum::decrypt(&ct_k, &priv_k, None)?;
    println!("Kyber 解密结果: {}", pt_k);

    // 私钥加密存储示例
    let pwd = SecretString::new(Box::from("strong_pass"));
    let container = SecureKeyContainer::encrypt_key(&pwd, &serde_json::to_vec(&priv_rsa)?, "RSA-2048")?;
    let json = container.to_json()?;
    println!("Encrypted key container: {}", json);

    Ok(())
}
```

## 功能详解

- **traditional 模块**：基于 RSA-2048/OAEP(SHA256) 的密钥生成、加密、解密。输出 Base64 编码的密文。
- **post_quantum 模块**：基于 Kyber768 KEM，通过 HKDF(SHA256) 派生 AES-GCM 密钥，进行数据加解密，并输出 Base64 编码。
- **secure_key 模块**：使用 Argon2id 派生密钥，对私钥数据进行 AES-256-GCM 加密，支持容器的 JSON 序列化与反序列化。
- **CLI 工具**：提供 `traditional` 与 `post-quantum` 子命令的加密/解密操作，以及 `generate-completions` 用于生成 Shell 补全脚本。

## 测试

运行所有单元测试：

```bash
cargo test
```

单独测试 core 库：

```bash
cd core
cargo test
```

## 贡献

欢迎提交 Issue 或 Pull Request，请确保：

1. 代码遵循 Rust 风格指南。
2. 新增功能或修复提交包含相应测试。
3. 文档更新保持同步。

## 许可

MPL LICENSE 2.0
