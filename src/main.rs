use clap::{CommandFactory, Parser, Subcommand};
use q_seal::{post_quantum, secure_key::SecureKeyContainer, traditional};
use rsa::RsaPublicKey;
use std::fs;
use std::io::{self, Write};

const TRADITIONAL_DEFAULT_KEY_FILE: &str = "rsa_key.json";
const TRADITIONAL_DEFAULT_DATA_FILE: &str = "rsa_ciphertext.b64";
const POST_QUANTUM_DEFAULT_KEY_FILE: &str = "kyber_key.json";
const POST_QUANTUM_DEFAULT_DATA_FILE: &str = "kyber_ciphertext.b64";

#[derive(Parser)]
#[command(author, version, about, long_about = "一个用于传统和后量子加密的工具。")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 传统 RSA 加密/解密。
    Traditional {
        #[command(subcommand)]
        action: Action,
    },
    /// 后量子 Kyber 加密/解密。
    PostQuantum {
        #[command(subcommand)]
        action: Action,
    },
    /// 为指定的 shell 生成补全脚本
    GenerateCompletions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum Action {
    /// 加密一个文本字符串。
    Encrypt {
        /// 要加密的文本。
        text: String,
        /// 指定私钥输出文件的路径。
        #[arg(long("key-out"))]
        key_output_path: Option<String>,
        /// 指定加密数据输出文件的路径。
        #[arg(long("data-out"))]
        data_output_path: Option<String>,
        /// 不将输出写入任何文件，仅在控制台显示。
        #[arg(long, default_value_t = false)]
        no_file: bool,
        /// 用于加密私钥的密码。如果不提供，将在命令行提示输入。
        #[arg(long)]
        password: Option<String>,
        /// 不加密私钥（不安全，不推荐）。
        #[arg(long, default_value_t = false)]
        no_password: bool,
    },
    /// 从文件或命令行参数解密密文。
    Decrypt {
        /// 要解密的文本 (Base64)。如果省略，将从 --data 指定的文件中读取。
        text: Option<String>,
        /// 私钥文件的路径。
        #[arg(short, long)]
        key: Option<String>,
        /// 加密数据文件的路径。当未直接提供要解密的文本时使用。
        #[arg(short, long)]
        data: Option<String>,
        /// 用于解密私钥的密码。如果不提供，将在命令行提示输入。
        #[arg(long)]
        password: Option<String>,
    },
}

// 安全地从用户获取密码
fn get_password(prompt: &str, confirm: bool) -> Result<String, Box<dyn std::error::Error>> {
    print!("{}", prompt);
    io::stdout().flush()?;
    
    let password = rpassword::read_password()?;
    
    if confirm && !password.is_empty() {
        print!("请再次输入密码以确认: ");
        io::stdout().flush()?;
        let confirm_password = rpassword::read_password()?;
        
        if password != confirm_password {
            return Err("密码不匹配".into());
        }
    }
    
    Ok(password)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

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

fn handle_traditional(action: Action) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rsa::rand_core::OsRng;
    match action {
        Action::Encrypt {
            text,
            key_output_path,
            data_output_path,
            no_file,
            password,
            no_password,
        } => {
            let (pub_key_struct, priv_key_struct) = traditional::generate_keypair(&mut rng)?;

            let rsa_pub_key = RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&pub_key_struct.n),
                rsa::BigUint::from_bytes_be(&pub_key_struct.e),
            )?;

            let encrypted = traditional::encrypt(&text, &rsa_pub_key, &mut rng)?;
            let private_key_json = serde_json::to_string_pretty(&priv_key_struct)?;

            println!("--- 传统 RSA 加密 ---");
            
            if !no_file {
                let key_path = key_output_path.as_deref().unwrap_or(TRADITIONAL_DEFAULT_KEY_FILE);
                let data_path = data_output_path.as_deref().unwrap_or(TRADITIONAL_DEFAULT_DATA_FILE);
                
                // 保存加密数据
                fs::write(data_path, &encrypted)?;
                println!("加密数据已保存到: {}", data_path);
                
                // 处理私钥
                if no_password {
                    // 直接保存未加密的私钥（不安全）
                    println!("警告: 私钥未加密保存，这是不安全的!");
                    println!("私钥 (JSON 格式):");
                    println!("{}", private_key_json);
                    fs::write(key_path, &private_key_json)?;
                    println!("私钥已保存到: {}", key_path);
                } else {
                    // 获取密码
                    let pwd = if let Some(p) = password {
                        p
                    } else {
                        get_password("请输入密码来加密私钥: ", true)?
                    };
                    
                    if pwd.is_empty() {
                        return Err("密码不能为空".into());
                    }
                    
                    // 加密私钥
                    let container = SecureKeyContainer::encrypt_key(
                        &pwd, 
                        private_key_json.as_bytes(), 
                        "RSA-4096"
                    )?;
                    
                    // 保存加密后的私钥
                    let secure_json = container.to_json()?;
                    fs::write(key_path, &secure_json)?;
                    println!("加密后的私钥已保存到: {}", key_path);
                    println!("请记住您的密码，它无法被恢复!");
                }
                
                println!("\n加密后的数据 (Base64):");
                println!("{}", encrypted);
            } else {
                // 只在控制台显示
                println!("私钥 (JSON 格式, 请妥善保管!):");
                println!("{}", private_key_json);
                println!("\n加密后的数据 (Base64):");
                println!("{}", encrypted);
            }
        }
        Action::Decrypt {
            text,
            key,
            data,
            password,
        } => {
            let key_path = key.as_deref().unwrap_or(TRADITIONAL_DEFAULT_KEY_FILE);

            // 读取加密数据
            let data_str = if let Some(ciphertext) = text {
                ciphertext
            } else {
                let data_path = data
                    .as_deref()
                    .unwrap_or(TRADITIONAL_DEFAULT_DATA_FILE);
                fs::read_to_string(data_path)
                    .map_err(|e| format!("无法读取数据文件 '{}': {}", data_path, e))?
            };

            // 读取密钥文件
            let key_str = fs::read_to_string(key_path)
                .map_err(|e| format!("无法读取密钥文件 '{}': {}", key_path, e))?;
            
            // 判断密钥格式：是JSON对象还是加密的容器
            let is_encrypted = key_str.trim().starts_with('{') && 
                               key_str.contains("\"encrypted_key\"");
            
            let priv_key_struct: traditional::PrivateKey = if is_encrypted {
                // 解析加密的密钥容器
                let container = SecureKeyContainer::from_json(&key_str)?;
                
                // 获取密码
                let pwd = if let Some(p) = password {
                    p
                } else {
                    get_password("请输入密码来解密私钥: ", false)?
                };
                
                // 解密私钥
                let decrypted_key = container.decrypt_key(&pwd)?;
                let json_str = String::from_utf8(decrypted_key)?;
                
                // 解析为私钥结构
                serde_json::from_str(&json_str)?
            } else {
                // 直接解析未加密的私钥
                serde_json::from_str(&key_str)?
            };

            // 解密数据
            let decrypted = traditional::decrypt_with_key_struct(&data_str, &priv_key_struct)?;

            println!("--- 传统 RSA 解密 ---");
            println!("解密后的文本:");
            println!("{}", decrypted);
        }
    }
    Ok(())
}

fn handle_post_quantum(action: Action) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::rng();
    match action {
        Action::Encrypt {
            text,
            key_output_path,
            data_output_path,
            no_file,
            password,
            no_password,
        } => {
            let (pub_key, priv_key) = post_quantum::generate_keypair();
            let encrypted = post_quantum::encrypt(&text, &pub_key, None, &mut rng)?;
            let priv_key_b64 = priv_key.to_base64();

            println!("--- 后量子 Kyber 加密 ---");
            
            if !no_file {
                let key_path = key_output_path.as_deref().unwrap_or(POST_QUANTUM_DEFAULT_KEY_FILE);
                let data_path = data_output_path.as_deref().unwrap_or(POST_QUANTUM_DEFAULT_DATA_FILE);
                
                // 保存加密数据
                fs::write(data_path, &encrypted)?;
                println!("加密数据已保存到: {}", data_path);
                
                // 处理私钥
                if no_password {
                    // 直接保存未加密的私钥（不安全）
                    println!("警告: 私钥未加密保存，这是不安全的!");
                    println!("私钥 (Base64 格式):");
                    println!("{}", priv_key_b64);
                    fs::write(key_path, &priv_key_b64)?;
                    println!("私钥已保存到: {}", key_path);
                } else {
                    // 获取密码
                    let pwd = if let Some(p) = password {
                        p
                    } else {
                        get_password("请输入密码来加密私钥: ", true)?
                    };
                    
                    if pwd.is_empty() {
                        return Err("密码不能为空".into());
                    }
                    
                    // 加密私钥
                    let container = SecureKeyContainer::encrypt_key(
                        &pwd, 
                        priv_key_b64.as_bytes(), 
                        "Kyber-1024"
                    )?;
                    
                    // 保存加密后的私钥
                    let secure_json = container.to_json()?;
                    fs::write(key_path, &secure_json)?;
                    println!("加密后的私钥已保存到: {}", key_path);
                    println!("请记住您的密码，它无法被恢复!");
                }
                
                println!("\n加密后的数据 (Base64):");
                println!("{}", encrypted);
            } else {
                // 只在控制台显示
                println!("私钥 (Base64 格式, 请妥善保管!):");
                println!("{}", priv_key_b64);
                println!("\n加密后的数据 (Base64):");
                println!("{}", encrypted);
            }
        }
        Action::Decrypt {
            text,
            key,
            data,
            password,
        } => {
            let key_path = key.as_deref().unwrap_or(POST_QUANTUM_DEFAULT_KEY_FILE);

            // 读取加密数据
            let data_b64 = if let Some(ciphertext) = text {
                ciphertext
            } else {
                let data_path = data
                    .as_deref()
                    .unwrap_or(POST_QUANTUM_DEFAULT_DATA_FILE);
                fs::read_to_string(data_path)
                    .map_err(|e| format!("无法读取数据文件 '{}': {}", data_path, e))?
            };

            // 读取密钥文件
            let key_content = fs::read_to_string(key_path)
                .map_err(|e| format!("无法读取密钥文件 '{}': {}", key_path, e))?;
            
            // 判断密钥格式：是Base64字符串还是加密的JSON容器
            let is_encrypted = key_content.trim().starts_with('{') && 
                               key_content.contains("\"encrypted_key\"");
            
            let priv_key = if is_encrypted {
                // 解析加密的密钥容器
                let container = SecureKeyContainer::from_json(&key_content)?;
                
                // 获取密码
                let pwd = if let Some(p) = password {
                    p
                } else {
                    get_password("请输入密码来解密私钥: ", false)?
                };
                
                // 解密私钥
                let decrypted_key = container.decrypt_key(&pwd)?;
                let key_b64 = String::from_utf8(decrypted_key)?;
                
                // 解析为私钥
                post_quantum::PrivateKey::from_base64(&key_b64)?
            } else {
                // 直接解析未加密的私钥
                post_quantum::PrivateKey::from_base64(&key_content)?
            };

            // 解密数据
            let decrypted = post_quantum::decrypt(&data_b64, &priv_key, None)?;

            println!("--- 后量子 Kyber 解密 ---");
            println!("解密后的文本:");
            println!("{}", decrypted);
        }
    }
    Ok(())
}
