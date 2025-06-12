use crate::error::AppError;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use argon2::{
    Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString},
};
use base64::{Engine as _, engine::general_purpose};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::fmt;

// Argon2 参数的推荐值 (基于 OWASP 建议)
// 内存成本 (m): 19 MiB (19 * 1024 = 19456 KiB)
const ARGON2_MEM_COST: u32 = 19456;
// 时间成本 (t): 迭代次数
const ARGON2_TIME_COST: u32 = 2;
// 并行度 (p): 并行线程数
const ARGON2_PARALLELISM: u32 = 1;

// 安全密钥存储格式
#[derive(Serialize, Deserialize)]
pub struct SecureKeyContainer {
    // Argon2 参数
    pub salt: String,     // Base64 编码的盐
    pub mem_cost: u32,    // 内存成本参数
    pub time_cost: u32,   // 时间成本参数
    pub parallelism: u32, // 并行度参数

    // AES-GCM 参数
    pub nonce: String, // Base64 编码的随机数

    // 加密后的密钥数据
    pub encrypted_key: String, // Base64 编码的加密密钥

    // 元数据
    pub algorithm: String,  // 密钥类型 (如 "RSA-4096" 或 "Kyber-1024")
    pub created_at: String, // ISO 8601 格式的创建时间
}

impl fmt::Debug for SecureKeyContainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureKeyContainer")
            .field("algorithm", &self.algorithm)
            .field("created_at", &self.created_at)
            .field("salt", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("encrypted_key", &"[REDACTED]")
            .finish()
    }
}

impl SecureKeyContainer {
    // 使用密码加密密钥
    pub fn encrypt_key(
        password: &SecretString,
        key_data: &[u8],
        algorithm: &str,
    ) -> Result<Self, AppError> {
        // 生成盐
        let salt = SaltString::generate(&mut OsRng);

        // 创建 Argon2 实例
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            Version::V0x13,
            Params::new(ARGON2_MEM_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, None)
                .map_err(|e| AppError::SecureKey(format!("Argon2 参数错误: {:?}", e)))?,
        );

        // 从密码派生加密密钥
        let password_hash = argon2
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .map_err(|e| AppError::SecureKey(format!("密码哈希错误: {:?}", e)))?;

        // 提取哈希值作为加密密钥
        let hash_bytes = password_hash
            .hash
            .ok_or_else(|| AppError::SecureKey("无法从 Argon2 哈希中提取字节".to_string()))?;
        let aes_key = Key::<Aes256Gcm>::from_slice(&hash_bytes.as_bytes()[0..32]);

        // 创建 AES-GCM 加密器
        let cipher = Aes256Gcm::new(aes_key);

        // 生成随机数 (nonce)
        let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);

        // 加密密钥数据
        let encrypted_key = cipher.encrypt(&nonce_bytes, key_data)?;

        // 获取当前时间
        let now = chrono::Utc::now();
        let created_at = now.to_rfc3339();

        Ok(SecureKeyContainer {
            salt: salt.as_str().to_string(),
            mem_cost: ARGON2_MEM_COST,
            time_cost: ARGON2_TIME_COST,
            parallelism: ARGON2_PARALLELISM,
            nonce: general_purpose::STANDARD.encode(nonce_bytes),
            encrypted_key: general_purpose::STANDARD.encode(encrypted_key),
            algorithm: algorithm.to_string(),
            created_at,
        })
    }

    // 使用密码解密密钥
    pub fn decrypt_key(&self, password: &SecretString) -> Result<Vec<u8>, AppError> {
        // 解析盐
        let salt = SaltString::from_b64(&self.salt)
            .map_err(|e| AppError::SecureKey(format!("无效的盐: {}", e)))?;

        // 创建 Argon2 实例，使用此密钥容器中存储的参数
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            Version::V0x13,
            Params::new(self.mem_cost, self.time_cost, self.parallelism, None)
                .map_err(|e| AppError::SecureKey(format!("Argon2 参数错误: {:?}", e)))?,
        );

        // 从密码派生加密密钥
        let password_hash = argon2
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .map_err(|e| AppError::SecureKey(format!("密码哈希错误: {:?}", e)))?;

        // 提取哈希值作为解密密钥
        let hash_bytes = password_hash
            .hash
            .ok_or_else(|| AppError::SecureKey("无法从 Argon2 哈希中提取字节".to_string()))?;
        let aes_key = Key::<Aes256Gcm>::from_slice(&hash_bytes.as_bytes()[0..32]);

        // 创建 AES-GCM 解密器
        let cipher = Aes256Gcm::new(aes_key);

        // 解码 nonce
        let nonce_bytes = general_purpose::STANDARD.decode(&self.nonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 解码加密的密钥数据
        let encrypted_key = general_purpose::STANDARD.decode(&self.encrypted_key)?;

        // 解密密钥数据
        let decrypted_key = cipher
            .decrypt(nonce, encrypted_key.as_ref())
            .map_err(|_| AppError::SecureKey("密码错误或密钥已损坏".to_string()))?;

        Ok(decrypted_key)
    }

    // 将容器序列化为 JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    // 从 JSON 反序列化
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    // 测试加密和解密是否能成功往返
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = SecretString::new(Box::from("correct_password"));
        let key_data = b"this is a very secret key data";
        let algorithm = "TEST-ALG-ROUNDTRIP";

        // 加密密钥
        let container = SecureKeyContainer::encrypt_key(&password, key_data, algorithm).unwrap();

        // 使用正确的密码解密
        let decrypted_key = container.decrypt_key(&password).unwrap();

        // 验证解密后的密钥与原始密钥相同
        assert_eq!(decrypted_key, key_data);
    }

    // 测试使用错误密码解密时是否会失败
    #[test]
    fn test_decrypt_with_wrong_password() {
        let password = SecretString::new(Box::from("correct_password"));
        let wrong_password = SecretString::new(Box::from("wrong_password"));
        let key_data = b"another secret key";
        let algorithm = "TEST-ALG-WRONG-PASS";

        // 加密密钥
        let container = SecureKeyContainer::encrypt_key(&password, key_data, algorithm).unwrap();

        // 尝试使用错误的密码解密
        let result = container.decrypt_key(&wrong_password);

        // 验证结果是错误
        assert!(result.is_err());

        // 验证错误信息是否符合预期
        assert_eq!(
            result.unwrap_err().to_string(),
            "安全密钥容器错误: 密码错误或密钥已损坏"
        );
    }

    // 测试 JSON 序列化和反序列化的往返过程
    #[test]
    fn test_json_serialization_roundtrip() {
        let password = SecretString::new(Box::from("json_test_password"));
        let key_data = b"data for json serialization test";
        let algorithm = "JSON-TEST-ALG";

        // 创建一个密钥容器
        let original_container =
            SecureKeyContainer::encrypt_key(&password, key_data, algorithm).unwrap();

        // 序列化为 JSON
        let json_data = original_container.to_json().unwrap();

        // 从 JSON 反序列化
        let deserialized_container = SecureKeyContainer::from_json(&json_data).unwrap();

        // 验证反序列化后的容器依然可以正常工作
        let decrypted_key = deserialized_container.decrypt_key(&password).unwrap();
        assert_eq!(decrypted_key, key_data);

        // 验证一些字段在序列化后保持不变
        assert_eq!(
            original_container.algorithm,
            deserialized_container.algorithm
        );
        assert_eq!(original_container.salt, deserialized_container.salt);
        assert_eq!(original_container.nonce, deserialized_container.nonce);
    }

    // 测试加密空数据的情况
    #[test]
    fn test_encrypt_empty_key_data() {
        let password = SecretString::new(Box::from("password_for_empty_data".to_string()));
        let key_data = b""; // 空的密钥数据
        let algorithm = "EMPTY-DATA-TEST-ALG";

        // 加密空的密钥数据
        let container = SecureKeyContainer::encrypt_key(&password, key_data, algorithm).unwrap();

        // 解密并验证结果是否为空
        let decrypted_key = container.decrypt_key(&password).unwrap();
        assert_eq!(decrypted_key, key_data);
        assert!(decrypted_key.is_empty());
    }
}
