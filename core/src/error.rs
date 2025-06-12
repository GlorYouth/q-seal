use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON 解析错误: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 解码错误: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("UTF-8 转换错误: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("传统加密错误: {0}")]
    Traditional(#[from] crate::traditional::Error),

    #[error("后量子加密错误: {0}")]
    PostQuantum(#[from] crate::post_quantum::Error),

    #[error("安全密钥容器错误: {0}")]
    SecureKey(String),

    #[error("密码不能为空")]
    EmptyPassword,

    #[error("密码不匹配")]
    PasswordMismatch,
    
    #[error("无效的输入: {0}")]
    InvalidInput(String),
}

impl From<aes_gcm::Error> for AppError {
    fn from(err: aes_gcm::Error) -> Self {
        AppError::SecureKey(format!("AES-GCM 操作失败: {}", err))
    }
}

impl From<rsa::Error> for AppError {
    fn from(err: rsa::Error) -> Self {
        AppError::SecureKey(format!("RSA 操作失败: {}", err))
    }
} 