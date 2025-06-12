use clap::{ArgGroup, CommandFactory, Parser, Subcommand};
use q_seal::{
    error::AppError, post_quantum, secure_key::SecureKeyContainer, traditional,
};
use rsa::RsaPublicKey;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use zeroize::Zeroize;
use secrecy::SecretString;

const TRADITIONAL_DEFAULT_KEY_FILE: &str = "rsa_key.json";
const TRADITIONAL_DEFAULT_DATA_FILE: &str = "rsa_ciphertext.b64";
const POST_QUANTUM_DEFAULT_KEY_FILE: &str = "kyber_key.json";
const POST_QUANTUM_DEFAULT_DATA_FILE: &str = "kyber_ciphertext.b64";

type AppResult<T> = Result<T, AppError>;

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
    /// 加密一个文本字符串或一个文件。
    #[command(group(ArgGroup::new("source").required(true).args(["text", "input_file"])))]
    Encrypt {
        /// 要加密的文本字符串。与 --in 互斥。
        #[arg(long)]
        text: Option<String>,
        /// 要加密的输入文件路径。与 --text 互斥。
        #[arg(long("in"))]
        input_file: Option<String>,
        /// 加密数据输出文件的路径。
        #[arg(long("out"))]
        output_file: Option<String>,
        /// 指定私钥输出文件的路径。
        #[arg(long("key-out"))]
        key_output_path: Option<String>,
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
        /// 要解密的文本 (Base64)。如果省略，将从 --in 指定的文件中读取。
        #[arg(long)]
        text: Option<String>,
        /// 私钥文件的路径。
        #[arg(short, long)]
        key: Option<String>,
        /// 加密数据文件的路径。当未直接提供 --text 参数时使用。
        #[arg(long("in"))]
        input_file: Option<String>,
        /// 解密后内容的输出文件路径。如果省略，将尝试打印到控制台。
        #[arg(long("out"))]
        output_file: Option<String>,
        /// 用于解密私钥的密码。如果不提供，将在命令行提示输入。
        #[arg(long)]
        password: Option<String>,
    },
}

// 安全地从用户获取密码
fn get_password(prompt: &str, confirm: bool) -> AppResult<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    
    let mut password = rpassword::read_password()?;
    
    if confirm && !password.is_empty() {
        print!("请再次输入密码以确认: ");
        io::stdout().flush()?;
        let mut confirm_password = rpassword::read_password()?;
        
        if password != confirm_password {
            confirm_password.zeroize();
            return Err(AppError::PasswordMismatch);
        }
        // 清除确认密码
        confirm_password.zeroize();
    }
    
    Ok(password)
}

fn main() -> AppResult<()> {
    let cli = Cli::parse();

    if let Err(e) = run_app(cli) {
        eprintln!("错误: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

fn run_app(cli: Cli) -> AppResult<()> {
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

fn handle_traditional(action: Action) -> AppResult<()> {
    match action {
        Action::Encrypt {
            text,
            input_file,
            output_file,
            key_output_path,
            no_file,
            password,
            no_password,
        } => {
            let encrypt_fn = |data: &[u8]| -> AppResult<(String, String)> {
                let mut rng = rsa::rand_core::OsRng;
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
                "RSA-4096",
                "--- 传统 RSA 加密 ---",
            )
        }
        Action::Decrypt {
            text,
            key,
            input_file,
            output_file,
            password,
        } => {
            let decrypt_from_key_str =
                |key_str: &str, data_str: &str| -> AppResult<Vec<u8>> {
                    let priv_key: traditional::PrivateKey = serde_json::from_str(key_str)?;
                    Ok(Vec::from(traditional::decrypt_with_key_struct(
                        data_str,
                        &priv_key,
                    )?))
                };

            let decrypt_from_key_bytes =
                |key_bytes: &[u8], data_str: &str| -> AppResult<Vec<u8>> {
                    let key_str = String::from_utf8(key_bytes.to_vec())?;
                    let priv_key: traditional::PrivateKey = serde_json::from_str(&key_str)?;
                    Ok(Vec::from(traditional::decrypt_with_key_struct(
                        data_str,
                        &priv_key,
                    )?))
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

fn handle_post_quantum(action: Action) -> AppResult<()> {
    match action {
        Action::Encrypt {
            text,
            input_file,
            output_file,
            key_output_path,
            no_file,
            password,
            no_password,
        } => {
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
                "Kyber-1024",
                "--- 后量子 Kyber 加密 ---",
            )
        }
        Action::Decrypt {
            text,
            key,
            input_file,
            output_file,
            password,
        } => {
            let decrypt_from_key_str =
                |key_str: &str, data_str: &str| -> AppResult<Vec<u8>> {
                    let priv_key = post_quantum::PrivateKey::from_base64(key_str)?;
                    Ok(Vec::from(post_quantum::decrypt(data_str, &priv_key, None)?))
                };

            let decrypt_from_key_bytes =
                |key_bytes: &[u8], data_str: &str| -> AppResult<Vec<u8>> {
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

// --- Helper Functions ---

fn get_input_data(
    text: Option<String>,
    input_file: Option<String>,
) -> AppResult<Vec<u8>> {
    if let Some(text) = text {
        Ok(text.as_bytes().to_vec())
    } else if let Some(path) = input_file {
        fs::read(&path).map_err(|e| {
            AppError::Io(e)
        })
    } else {
        // This case should be prevented by clap's ArgGroup
        unreachable!("需要提供 --text 或 --in <文件>");
    }
}


// --- Generic Action Handlers ---

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
    println!("{}", title);

    let (encrypted_data, private_key_string) = encrypt_fn(input_data)?;

    if no_file {
        // 只在控制台显示
        println!("私钥 ({} 格式, 请妥善保管!):", key_format_name);
        println!("{}", private_key_string);
        println!("\n加密后的数据 (Base64):");
        println!("{}", encrypted_data);
    } else {
        let key_path = key_output_path.as_deref().unwrap_or(default_key_file);
        let data_path = output_file.as_deref().unwrap_or(default_data_file);

        // 保存加密数据
        fs::write(data_path, &encrypted_data)?;
        println!("加密数据已保存到: {}", data_path);
        
        // 处理私钥
        if no_password {
            // 直接保存未加密的私钥（不安全）
            println!("警告: 私钥未加密保存，这是不安全的!");
            println!("私钥 ({} 格式):", key_format_name);
            println!("{}", private_key_string);
            fs::write(key_path, &private_key_string)?;
            println!("私钥已保存到: {}", key_path);
        } else {
            // 获取密码
            let pwd = if let Some(p) = password {
                p
            } else {
                get_password("请输入密码来加密私钥: ", true)?
            };
            
            if pwd.is_empty() {
                return Err(AppError::EmptyPassword);
            }
            
            // Wrap password in SecretString for secure key encryption
            let secret_pwd = SecretString::new(Box::from(pwd));
            
            // 加密私钥
            let container = SecureKeyContainer::encrypt_key(
                &secret_pwd, 
                private_key_string.as_bytes(),
                algorithm_id,
            )?;
            
            // 保存加密后的私钥
            let secure_json = container.to_json()?;
            fs::write(key_path, &secure_json)?;
            println!("加密后的私钥已保存到: {}", key_path);
            println!("请记住您的密码，它无法被恢复!");
        }
        
        println!("\n加密后的数据 (Base64):");
        println!("{}", encrypted_data);
    }

    Ok(())
}

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
    let key_path = key_path_opt.as_deref().unwrap_or(default_key_file);

    // 优先使用命令行参数中的密文，否则从文件读取
    let data_str = if let Some(ciphertext) = text {
        ciphertext
    } else {
        let data_path = data_path_opt
            .as_deref()
            .unwrap_or(default_data_file);
        fs::read_to_string(data_path)?
    };
                
    // 读取密钥文件
    let key_content = fs::read_to_string(key_path)?;

    // 判断密钥是否为加密容器
    let is_encrypted_container = key_content.trim().starts_with('{')
        && key_content.contains("\"encrypted_key\"");

    let decrypted = if is_encrypted_container {
        // 解析加密的密钥容器
        let container = SecureKeyContainer::from_json(&key_content)?;
        
        // 获取密码
        let pwd = if let Some(p) = password {
            p
        } else {
            get_password("请输入密码来解密私钥: ", false)?
        };
        
        // Wrap password in SecretString for secure key decryption
        let secret_pwd = SecretString::new(Box::from(pwd));
        
        // 解密私钥
        let decrypted_key_bytes = container.decrypt_key(&secret_pwd)?;
        
        // 调用特定于算法的解密函数（使用字节）
        decrypt_from_key_bytes(&decrypted_key_bytes, &data_str)?
    } else {
        // 直接使用未加密的密钥文件内容
        decrypt_from_key_str(&key_content, &data_str)?
    };

    println!("{}", title);
    if let Some(path) = output_file {
        fs::write(&path, &decrypted)?;
        println!("解密后的数据已保存到: {}", path);
    } else {
        match String::from_utf8(decrypted) {
            Ok(s) => {
                println!("解密后的文本:");
                println!("{}", s);
            }
            Err(_) => {
                println!("解密后的数据不是有效的 UTF-8 文本。");
                println!("请使用 --out <文件路径> 将其保存到文件。");
            }
        }
    }

    Ok(())
}
