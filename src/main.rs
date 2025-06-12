use clap::{Parser, Subcommand};
use q_seal::{post_quantum, traditional};
use rsa::RsaPublicKey;

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
}

#[derive(Subcommand)]
enum Action {
    /// 加密一个文本字符串。
    /// 此操作会生成一个新的密钥对，并打印私钥和密文。
    Encrypt {
        /// 要加密的文本。
        text: String,
    },
    /// 解密一个 JSON/Base64 编码的密文。
    Decrypt {
        /// 私钥。对于 RSA，这是一个 JSON 字符串；对于 Kyber，这是一个 Base64 字符串。
        #[arg(short, long)]
        key: String,
        /// 要解密的 Base64 编码的密文。
        data: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Traditional { action } => handle_traditional(action)?,
        Commands::PostQuantum { action } => handle_post_quantum(action)?,
    }

    Ok(())
}

fn handle_traditional(action: Action) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rsa::rand_core::OsRng;
    match action {
        Action::Encrypt { text } => {
            let (pub_key_struct, priv_key_struct) = traditional::generate_keypair(&mut rng)?;

            let rsa_pub_key = RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&pub_key_struct.n),
                rsa::BigUint::from_bytes_be(&pub_key_struct.e),
            )?;

            let encrypted = traditional::encrypt(&text, &rsa_pub_key, &mut rng)?;

            println!("--- 传统 RSA 加密 ---");
            println!("私钥 (JSON 格式, 请妥善保管!):");
            println!("{}", serde_json::to_string_pretty(&priv_key_struct)?);
            println!("\n加密后的数据 (Base64):");
            println!("{}", encrypted);
        }
        Action::Decrypt { key, data } => {
            let priv_key_struct: traditional::PrivateKey = serde_json::from_str(&key)?;
            let decrypted = traditional::decrypt_with_key_struct(&data, &priv_key_struct)?;

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
        Action::Encrypt { text } => {
            let (pub_key, priv_key) = post_quantum::generate_keypair();
            let encrypted = post_quantum::encrypt(&text, &pub_key, None, &mut rng)?;

            println!("--- 后量子 Kyber 加密 ---");
            println!("私钥 (Base64 格式, 请妥善保管!):");
            println!("{}", priv_key.to_base64());
            println!("\n加密后的数据 (Base64):");
            println!("{}", encrypted);
        }
        Action::Decrypt { key, data } => {
            let priv_key = post_quantum::PrivateKey::from_base64(&key)?;
            let decrypted = post_quantum::decrypt(&data, &priv_key, None)?;
            
            println!("--- 后量子 Kyber 解密 ---");
            println!("解密后的文本:");
            println!("{}", decrypted);
        }
    }
    Ok(())
}
