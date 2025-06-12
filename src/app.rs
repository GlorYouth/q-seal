use crate::cli::{Cli, Commands, Action};
use clap::CommandFactory;
use clap_complete;
use q_seal_core::{error::AppError, post_quantum, traditional, secure_key::SecureKeyContainer};
use rsa::{RsaPublicKey, rand_core::OsRng};
use secrecy::SecretString;
use zeroize::Zeroize;
use rand;
use std::{fs, io::{self, Read, Write}, path::Path};

/// 默认文件名常量
pub const TRADITIONAL_DEFAULT_KEY_FILE: &str = "rsa_key.json";
pub const TRADITIONAL_DEFAULT_DATA_FILE: &str = "rsa_ciphertext.b64";
pub const POST_QUANTUM_DEFAULT_KEY_FILE: &str = "kyber_key.json";
pub const POST_QUANTUM_DEFAULT_DATA_FILE: &str = "kyber_ciphertext.b64";

type AppResult<T> = Result<T, AppError>;

/// 安全地从用户获取密码
fn get_password(prompt: &str, confirm: bool) -> AppResult<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    if confirm && !password.is_empty() {
        print!("请再次输入密码以确认: ");
        io::stdout().flush()?;
        let mut confirm_password = rpassword::read_password()?;
        if password != confirm_password {
            confirm_password.zeroize();
            return Err(AppError::PasswordMismatch);
        }
        confirm_password.zeroize();
    }
    Ok(password)
}

/// 运行主逻辑
pub fn run_app(cli: Cli) -> AppResult<()> {
    match cli.command {
        Commands::Traditional { action } => handle_traditional(action)?,
        Commands::PostQuantum { action } => handle_post_quantum(action)?,
        Commands::GenerateCompletions { shell } => {
            let mut cmd = Cli::command();
            let bin_name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, bin_name, &mut io::stdout());
        }
    }
    Ok(())
}

/// 处理传统 RSA 子命令
fn handle_traditional(action: Action) -> AppResult<()> {
    match action {
        Action::Encrypt { text, input_file, output_file, key_output_path, no_file, password, no_password } => {
            let encrypt_fn = |data: &[u8]| -> AppResult<(String, String)> {
                let mut rng = OsRng;
                let (pub_key_struct, priv_key_struct) = traditional::generate_keypair(&mut rng)?;
                let rsa_pub_key = RsaPublicKey::new(
                    rsa::BigUint::from_bytes_be(&pub_key_struct.n),
                    rsa::BigUint::from_bytes_be(&pub_key_struct.e),
                )?;
                let encrypted_data = traditional::encrypt(data, &rsa_pub_key, &mut rng)?;
                let private_key_string = serde_json::to_string_pretty(&priv_key_struct)?;
                Ok((encrypted_data, private_key_string))
            };
            let input_data = get_input_data(text, input_file)?;
            handle_encrypt_action(
                &input_data,
                output_file,
                key_output_path,
                no_file,
                password,
                no_password,
                encrypt_fn,
                "JSON",
                TRADITIONAL_DEFAULT_KEY_FILE,
                TRADITIONAL_DEFAULT_DATA_FILE,
                "RSA-2048",
                "--- 传统 RSA 加密 ---",
            )
        }
        Action::Decrypt { text, key, input_file, output_file, password } => {
            let decrypt_from_key_str = |key_str: &str, data_str: &str| -> AppResult<Vec<u8>> {
                let priv_key: traditional::PrivateKey = serde_json::from_str(key_str)?;
                Ok(Vec::from(traditional::decrypt_with_key_struct(data_str, &priv_key)?))
            };
            let decrypt_from_key_bytes = |key_bytes: &[u8], data_str: &str| -> AppResult<Vec<u8>> {
                let key_str = String::from_utf8(key_bytes.to_vec())?;
                let priv_key: traditional::PrivateKey = serde_json::from_str(&key_str)?;
                Ok(Vec::from(traditional::decrypt_with_key_struct(data_str, &priv_key)?))
            };
            handle_decrypt_action(
                text,
                key,
                input_file,
                output_file,
                password,
                TRADITIONAL_DEFAULT_KEY_FILE,
                TRADITIONAL_DEFAULT_DATA_FILE,
                decrypt_from_key_str,
                decrypt_from_key_bytes,
                "--- 传统 RSA 解密 ---",
            )
        }
    }
}

/// 处理后量子 Kyber 子命令
fn handle_post_quantum(action: Action) -> AppResult<()> {
    match action {
        Action::Encrypt { text, input_file, output_file, key_output_path, no_file, password, no_password } => {
            let encrypt_fn = |data: &[u8]| -> AppResult<(String, String)> {
                let mut rng = rand::rng();
                let (pub_key, priv_key) = post_quantum::generate_keypair();
                let encrypted_data = post_quantum::encrypt(data, &pub_key, None, &mut rng)?;
                let private_key_string = priv_key.to_base64();
                Ok((encrypted_data, private_key_string))
            };
            let input_data = get_input_data(text, input_file)?;
            handle_encrypt_action(
                &input_data,
                output_file,
                key_output_path,
                no_file,
                password,
                no_password,
                encrypt_fn,
                "Base64",
                POST_QUANTUM_DEFAULT_KEY_FILE,
                POST_QUANTUM_DEFAULT_DATA_FILE,
                "Kyber-768",
                "--- 后量子 Kyber 加密 ---",
            )
        }
        Action::Decrypt { text, key, input_file, output_file, password } => {
            let decrypt_from_key_str = |key_str: &str, data_str: &str| -> AppResult<Vec<u8>> {
                let priv_key = post_quantum::PrivateKey::from_base64(key_str)?;
                Ok(Vec::from(post_quantum::decrypt(data_str, &priv_key, None)?))
            };
            let decrypt_from_key_bytes = |key_bytes: &[u8], data_str: &str| -> AppResult<Vec<u8>> {
                let key_b64 = String::from_utf8(key_bytes.to_vec())?;
                let priv_key = post_quantum::PrivateKey::from_base64(&key_b64)?;
                Ok(Vec::from(post_quantum::decrypt(data_str, &priv_key, None)?))
            };
            handle_decrypt_action(
                text,
                key,
                input_file,
                output_file,
                password,
                POST_QUANTUM_DEFAULT_KEY_FILE,
                POST_QUANTUM_DEFAULT_DATA_FILE,
                decrypt_from_key_str,
                decrypt_from_key_bytes,
                "--- 后量子 Kyber 解密 ---",
            )
        }
    }
}

/// 读取输入：文本、文件或标准输入
fn get_input_data(text: Option<String>, input_file: Option<String>) -> AppResult<Vec<u8>> {
    if let Some(text) = text {
        Ok(text.into_bytes())
    } else if let Some(path) = input_file {
        if path == "-" {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        } else {
            fs::read(&path).map_err(AppError::Io)
        }
    } else {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    }
}

/// 通用加密处理器
fn handle_encrypt_action(
    input_data: &[u8],
    output_file: Option<String>,
    key_output_path: Option<String>,
    no_file: bool,
    password: Option<String>,
    no_password: bool,
    encrypt_fn: impl FnOnce(&[u8]) -> AppResult<(String, String)>,
    key_format_name: &str,
    default_key_file: &str,
    default_data_file: &str,
    algorithm_id: &str,
    title: &str,
) -> AppResult<()> {
    // 打印加密标题
    println!("{}", title);
    // 提示等待
    println!("正在执行加密操作，请稍候...");
    io::stdout().flush()?;
    // 执行加密
    let (encrypted_data, private_key_string) = encrypt_fn(input_data)?;
    if no_file {
        println!("私钥 ({} 格式, 请妥善保管!):", key_format_name);
        println!("{}", private_key_string);
        println!("\n加密后的数据 (Base64):");
        println!("{}", encrypted_data);
    } else {
        let key_path = key_output_path.as_deref().unwrap_or(default_key_file);
        let data_path = output_file.as_deref().unwrap_or(default_data_file);
        // 保存加密数据
        if data_path == "-" {
            println!("{}", encrypted_data);
        } else {
            if Path::new(data_path).exists() {
                print!("文件 '{}' 已存在，是否覆盖？[y/N]: ", data_path);
                io::stdout().flush()?;
                let mut ans = String::new();
                io::stdin().read_line(&mut ans)?;
                if !ans.trim().eq_ignore_ascii_case("y") {
                    println!("已取消写入文件 {}", data_path);
                } else {
                    fs::write(data_path, &encrypted_data)?;
                    println!("加密数据已保存到: {}", data_path);
                }
            } else {
                fs::write(data_path, &encrypted_data)?;
                println!("加密数据已保存到: {}", data_path);
            }
        }
        // 私钥处理
        if no_password {
            println!("警告: 私钥未加密保存，这是不安全的!");
            println!("私钥 ({} 格式):", key_format_name);
            println!("{}", private_key_string);
            if key_path == "-" {
                println!("{}", private_key_string);
            } else {
                if Path::new(key_path).exists() {
                    print!("文件 '{}' 已存在，是否覆盖？[y/N]: ", key_path);
                    io::stdout().flush()?;
                    let mut ans = String::new(); io::stdin().read_line(&mut ans)?;
                    if ans.trim().eq_ignore_ascii_case("y") {
                        fs::write(key_path, &private_key_string)?;
                        println!("私钥已保存到: {}", key_path);
                    } else {
                        println!("已取消写入文件 {}", key_path);
                    }
                } else {
                    fs::write(key_path, &private_key_string)?;
                    println!("私钥已保存到: {}", key_path);
                }
            }
        } else {
            let pwd = if let Some(p) = password { p } else { get_password("请输入密码来加密私钥: ", true)? };
            if pwd.is_empty() { return Err(AppError::EmptyPassword); }
            let secret_pwd = SecretString::new(Box::from(pwd));
            let container = SecureKeyContainer::encrypt_key(&secret_pwd, private_key_string.as_bytes(), algorithm_id)?;
            let secure_json = container.to_json()?;
            if key_path == "-" {
                println!("{}", secure_json);
                println!("请妥善保存以上加密私钥 JSON");
            } else {
                if Path::new(key_path).exists() {
                    print!("文件 '{}' 已存在，是否覆盖？[y/N]: ", key_path);
                    io::stdout().flush()?;
                    let mut ans = String::new(); io::stdin().read_line(&mut ans)?;
                    if ans.trim().eq_ignore_ascii_case("y") {
                        fs::write(key_path, &secure_json)?;
                        println!("加密后的私钥已保存到: {}", key_path);
                        println!("请记住您的密码，它无法被恢复!");
                    } else {
                        println!("已取消写入文件 {}", key_path);
                    }
                } else {
                    fs::write(key_path, &secure_json)?;
                    println!("加密后的私钥已保存到: {}", key_path);
                    println!("请记住您的密码，它无法被恢复!");
                }
            }
        }
        println!("\n加密后的数据 (Base64):");
        println!("{}", encrypted_data);
    }
    Ok(())
}

/// 通用解密处理器
fn handle_decrypt_action(
    text: Option<String>,
    key_path_opt: Option<String>,
    data_path_opt: Option<String>,
    output_file: Option<String>,
    password: Option<String>,
    default_key_file: &str,
    default_data_file: &str,
    decrypt_from_key_str: impl FnOnce(&str, &str) -> AppResult<Vec<u8>>,
    decrypt_from_key_bytes: impl FnOnce(&[u8], &str) -> AppResult<Vec<u8>>,
    title: &str,
) -> AppResult<()> {
    println!("{}", title);
    println!("正在执行解密操作，请稍候...");
    io::stdout().flush()?;
    let key_path = key_path_opt.as_deref().unwrap_or(default_key_file);
    let data_str = if let Some(ciphertext) = text {
        ciphertext
    } else if let Some(path) = data_path_opt {
        if path == "-" {
            let mut s = String::new(); io::stdin().read_to_string(&mut s)?; s
        } else {
            fs::read_to_string(&path)?
        }
    } else {
        if default_data_file == "-" {
            let mut s = String::new(); io::stdin().read_to_string(&mut s)?; s
        } else {
            fs::read_to_string(default_data_file)?
        }
    };
    let key_content = fs::read_to_string(key_path)?;
    let is_encrypted_container = key_content.trim().starts_with('{') && key_content.contains("\"encrypted_key\"");
    let decrypted = if is_encrypted_container {
        let container = SecureKeyContainer::from_json(&key_content)?;
        let pwd = if let Some(p) = password { p } else { get_password("请输入密码来解密私钥: ", false)? };
        let secret_pwd = SecretString::new(Box::from(pwd));
        let decrypted_key_bytes = container.decrypt_key(&secret_pwd)?;
        decrypt_from_key_bytes(&decrypted_key_bytes, &data_str)?
    } else {
        decrypt_from_key_str(&key_content, &data_str)?
    };
    if let Some(path) = output_file {
        if path == "-" {
            io::stdout().write_all(&decrypted)?;
        } else {
            if Path::new(&path).exists() {
                print!("文件 '{}' 已存在，是否覆盖？[y/N]: ", path);
                io::stdout().flush()?;
                let mut ans = String::new(); io::stdin().read_line(&mut ans)?;
                if !ans.trim().eq_ignore_ascii_case("y") { println!("已取消写入文件 {}", path); return Ok(()); }
            }
            fs::write(&path, &decrypted)?;
            println!("解密后的数据已保存到: {}", path);
        }
    } else {
        match String::from_utf8(decrypted.clone()) {
            Ok(s) => {
                println!("解密后的文本:");
                println!("{}", s);
            }
            Err(_) => {
                io::stdout().write_all(&decrypted)?;
            }
        }
    }
    Ok(())
} 