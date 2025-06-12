use clap::{ArgGroup, Parser, Subcommand};
use clap_complete::Shell;

/// 命令行接口定义
#[derive(Parser)]
#[command(author, version, about, long_about = "一个用于传统和后量子加密的工具。")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// 顶层子命令
#[derive(Subcommand)]
pub enum Commands {
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
        shell: Shell,
    },
}

/// 具体操作：加密或解密
#[derive(Subcommand)]
pub enum Action {
    /// 加密一个文本字符串或一个文件。
    #[command(group(ArgGroup::new("source").required(true).args(["text", "input_file"])))]
    Encrypt {
        /// 要加密的文本字符串。与 --in 互斥。
        #[arg(long)]
        text: Option<String>,
        /// 要加密的输入文件路径。与 --text 互斥。
        #[arg(long = "in")]
        input_file: Option<String>,
        /// 加密数据输出文件的路径。
        #[arg(long = "out")]
        output_file: Option<String>,
        /// 指定私钥输出文件的路径。
        #[arg(long = "key-out")]
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
        #[arg(long = "in")]
        input_file: Option<String>,
        /// 解密后内容的输出文件路径。如果省略，将尝试打印到控制台。
        #[arg(long = "out")]
        output_file: Option<String>,
        /// 用于解密私钥的密码。如果不提供，将在命令行提示输入。
        #[arg(long)]
        password: Option<String>,
    },
} 