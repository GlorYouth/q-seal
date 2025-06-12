use clap::{CommandFactory, Parser, Subcommand};
use q_seal::{post_quantum, traditional};
use rsa::RsaPublicKey;
use std::fs;
use std::io;

const TRADITIONAL_DEFAULT_KEY_FILE: &str = "rsa_key.json";
const TRADITIONAL_DEFAULT_DATA_FILE: &str = "rsa_ciphertext.b64";
const POST_QUANTUM_DEFAULT_KEY_FILE: &str = "kyber_key.b64";
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
    },
    /// 从文件解密密文。
    Decrypt {
        /// 私钥文件的路径。
        #[arg(short, long)]
        key: Option<String>,
        /// 加密数据文件的路径。
        #[arg(short, long)]
        data: Option<String>,
    },
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
        } => {
            let (pub_key_struct, priv_key_struct) = traditional::generate_keypair(&mut rng)?;

            let rsa_pub_key = RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&pub_key_struct.n),
                rsa::BigUint::from_bytes_be(&pub_key_struct.e),
            )?;

            let encrypted = traditional::encrypt(&text, &rsa_pub_key, &mut rng)?;
            let private_key_json = serde_json::to_string_pretty(&priv_key_struct)?;

            println!("--- 传统 RSA 加密 ---");
            println!("私钥 (JSON 格式, 请妥善保管!):");
            println!("{}", private_key_json);
            println!("\n加密后的数据 (Base64):");
            println!("{}", encrypted);

            if !no_file {
                let key_path = key_output_path.as_deref().unwrap_or(TRADITIONAL_DEFAULT_KEY_FILE);
                let data_path = data_output_path.as_deref().unwrap_or(TRADITIONAL_DEFAULT_DATA_FILE);
                fs::write(key_path, &private_key_json)?;
                fs::write(data_path, &encrypted)?;
                println!("\n私钥已保存到: {}", key_path);
                println!("加密数据已保存到: {}", data_path);
            }
        }
        Action::Decrypt { key, data } => {
            let key_path = key.as_deref().unwrap_or(TRADITIONAL_DEFAULT_KEY_FILE);
            let data_path = data.as_deref().unwrap_or(TRADITIONAL_DEFAULT_DATA_FILE);

            let key_str = fs::read_to_string(key_path)
                .map_err(|e| format!("无法读取密钥文件 '{}': {}", key_path, e))?;
            let data_str = fs::read_to_string(data_path)
                .map_err(|e| format!("无法读取数据文件 '{}': {}", data_path, e))?;


            let priv_key_struct: traditional::PrivateKey = serde_json::from_str(&key_str)?;
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
        } => {
            let (pub_key, priv_key) = post_quantum::generate_keypair();
            let encrypted = post_quantum::encrypt(&text, &pub_key, None, &mut rng)?;
            let priv_key_b64 = priv_key.to_base64();

            println!("--- 后量子 Kyber 加密 ---");
            println!("私钥 (Base64 格式, 请妥善保管!):");
            println!("{}", &priv_key_b64);
            println!("\n加密后的数据 (Base64):");
            println!("{}", encrypted);

            if !no_file {
                let key_path = key_output_path.as_deref().unwrap_or(POST_QUANTUM_DEFAULT_KEY_FILE);
                let data_path = data_output_path.as_deref().unwrap_or(POST_QUANTUM_DEFAULT_DATA_FILE);
                fs::write(key_path, &priv_key_b64)?;
                fs::write(data_path, &encrypted)?;
                println!("\n私钥已保存到: {}", key_path);
                println!("加密数据已保存到: {}", data_path);
            }
        }
        Action::Decrypt { key, data } => {
            let key_path = key.as_deref().unwrap_or(POST_QUANTUM_DEFAULT_KEY_FILE);
            let data_path = data.as_deref().unwrap_or(POST_QUANTUM_DEFAULT_DATA_FILE);

            let key_b64 = fs::read_to_string(key_path)
                .map_err(|e| format!("无法读取密钥文件 '{}': {}", key_path, e))?;
            let data_b64 = fs::read_to_string(data_path)
                .map_err(|e| format!("无法读取数据文件 '{}': {}", data_path, e))?;


            let priv_key = post_quantum::PrivateKey::from_base64(&key_b64)?;
            let decrypted = post_quantum::decrypt(&data_b64, &priv_key, None)?;

            println!("--- 后量子 Kyber 解密 ---");
            println!("解密后的文本:");
            println!("{}", decrypted);
        }
    }
    Ok(())
}
