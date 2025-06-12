// 主入口文件：简化为模块调用
mod cli;
mod app;
use q_seal_core::error::AppError;
use std::process;
use clap::Parser;

/// 程序入口
fn main() -> Result<(), AppError> {
    // 解析命令行参数
    let cli = cli::Cli::parse();
    // 调用业务逻辑
    if let Err(e) = app::run_app(cli) {
        eprintln!("错误: {}", e);
        process::exit(1);
    }
    Ok(())
}
