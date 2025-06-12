use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hkdf::Hkdf;
use pqcrypto_kyber::*;
use pqcrypto_traits::kem::{
    Ciphertext, PublicKey as PqPublicKey, SecretKey as PqSecretKey, SharedSecret,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::error::Error as StdError;
use std::fmt;

// --- 常量定义 ---
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12; // AES-GCM 标准 Nonce 长度
const KYBER_CIPHERTEXT_LEN: usize = kyber768::ciphertext_bytes();

#[derive(Debug)]
pub enum Error {
    Base64(base64::DecodeError),
    Utf8(std::string::FromUtf8Error),
    Aes(aes_gcm::Error),
    InvalidData(&'static str),
    InvalidLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Base64(e) => write!(f, "Base64 aihwa: {}", e),
            Error::Utf8(e) => write!(f, "UTF-8 aihwa: {}", e),
            Error::Aes(e) => write!(f, "AES-GCM aihwa: {}", e),
            Error::InvalidData(msg) => write!(f, "Datha di-hau: {}", msg),
            Error::InvalidLength => write!(f, "Datha-thong-tu di-hau"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Base64(e) => Some(e),
            Error::Utf8(e) => Some(e),
            Error::Aes(_) => None,
            _ => None,
        }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64(e)
    }
}
impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::Utf8(e)
    }
}
impl From<aes_gcm::Error> for Error {
    fn from(e: aes_gcm::Error) -> Self {
        Error::Aes(e)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
    data: Vec<u8>,
}

impl PublicKey {
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.data)
    }

    pub fn from_base64(encoded: &str) -> Result<Self, Error> {
        let data = BASE64.decode(encoded)?;
        Ok(PublicKey { data })
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PrivateKey {
    data: Vec<u8>,
}

impl PrivateKey {
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.data)
    }

    pub fn from_base64(encoded: &str) -> Result<Self, Error> {
        let data = BASE64.decode(encoded)?;
        Ok(PrivateKey { data })
    }
}

/// 使用Kyber768生成随机密钥对
pub fn generate_keypair() -> (PublicKey, PrivateKey) {
    let (pk, sk) = kyber768::keypair();
    let public_key = PublicKey {
        data: pk.as_bytes().to_vec(),
    };
    let private_key = PrivateKey {
        data: sk.as_bytes().to_vec(),
    };
    (public_key, private_key)
}

/// 使用Kyber公钥和AES-GCM加密字符串
pub fn encrypt<R>(
    input: &[u8],
    public_key: &PublicKey,
    associated_data: Option<&[u8]>,
    rng: &mut R,
) -> Result<String, Error>
where
    R: RngCore + CryptoRng,
{
    let pk = kyber768::PublicKey::from_bytes(&public_key.data)
        .map_err(|_| Error::InvalidData("无效的公钥数据"))?;

    let (shared_secret, kyber_ciphertext) = kyber768::encapsulate(&pk);

    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(&[], &mut okm)
        .expect("32 bytes is a valid length for HKDF");
    let key = okm.into();

    let cipher = Aes256Gcm::new(&key);
    let mut nonce_data = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_data);
    let nonce = nonce_data.into();

    let payload = Payload {
        msg: input,
        aad: associated_data.unwrap_or(&[]),
    };

    let encrypted_message = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| Error::Aes(aes_gcm::Error))?;

    let mut result = Vec::new();
    result.extend_from_slice(&salt);
    result.extend_from_slice(kyber_ciphertext.as_bytes());
    result.extend_from_slice(&nonce_data);
    result.extend_from_slice(&encrypted_message);

    Ok(BASE64.encode(&result))
}

/// 使用Kyber私钥和AES-GCM解密字符串
pub fn decrypt(
    encrypted: &str,
    private_key: &PrivateKey,
    associated_data: Option<&[u8]>,
) -> Result<String, Error> {
    let encrypted_data = BASE64.decode(encrypted)?;

    let min_len = SALT_LEN + KYBER_CIPHERTEXT_LEN + NONCE_LEN;
    if encrypted_data.len() < min_len {
        return Err(Error::InvalidLength);
    }

    let (salt, rest) = encrypted_data.split_at(SALT_LEN);
    let (kyber_ciphertext_slice, rest) = rest.split_at(KYBER_CIPHERTEXT_LEN);
    let (nonce_data, encrypted_message) = rest.split_at(NONCE_LEN);

    let sk = kyber768::SecretKey::from_bytes(&private_key.data)
        .map_err(|_| Error::InvalidData("无效的私钥数据"))?;

    let ct = kyber768::Ciphertext::from_bytes(kyber_ciphertext_slice)
        .map_err(|_| Error::InvalidData("无效的密文数据"))?;

    let shared_secret = kyber768::decapsulate(&ct, &sk);

    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(&[], &mut okm)
        .expect("32 bytes is a valid length for HKDF");
    let key = okm.into();

    let cipher = Aes256Gcm::new(&key);
    let nonce_array: [u8; NONCE_LEN] = nonce_data
        .try_into()
        .map_err(|_| Error::InvalidData("Nonce 长度无效"))?;
    let nonce = nonce_array.into();

    let payload = Payload {
        msg: encrypted_message,
        aad: associated_data.unwrap_or(&[]),
    };

    let decrypted_message = cipher
        .decrypt(&nonce, payload)
        .map_err(|_| Error::Aes(aes_gcm::Error))?;

    String::from_utf8(decrypted_message).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rng;

    #[test]
    fn test_encrypt_decrypt_happy_path() {
        let test_input = "Hello, quantum world! This is a longer message to test encryption.";
        let (pub_key, priv_key) = generate_keypair();

        let encrypted = encrypt(test_input.as_bytes(), &pub_key, None, &mut rng()).unwrap();
        let decrypted = decrypt(&encrypted, &priv_key, None).unwrap();

        assert_eq!(test_input, decrypted);
    }

    #[test]
    fn test_key_serialization() {
        let (pub_key, priv_key) = generate_keypair();

        let pub_b64 = pub_key.to_base64();
        let priv_b64 = priv_key.to_base64();

        let restored_pub = PublicKey::from_base64(&pub_b64).unwrap();
        let restored_priv = PrivateKey::from_base64(&priv_b64).unwrap();

        assert_eq!(pub_key, restored_pub);
        assert_eq!(priv_key, restored_priv);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let test_input = "This message should not be decryptable.";
        let (pub_key, _) = generate_keypair();
        let (_, wrong_priv_key) = generate_keypair();

        let encrypted = encrypt(test_input.as_bytes(), &pub_key, None, &mut rng()).unwrap();
        let result = decrypt(&encrypted, &wrong_priv_key, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails_decryption() {
        let test_input = "Another message";
        let (pub_key, priv_key) = generate_keypair();

        let encrypted_b64 = encrypt(test_input.as_bytes(), &pub_key, None, &mut rng()).unwrap();
        let mut encrypted_data = BASE64.decode(&encrypted_b64).unwrap();

        // Flip a bit in the ciphertext part
        let last_byte_index = encrypted_data.len() - 1;
        encrypted_data[last_byte_index] ^= 0x01;

        let tampered_encrypted_b64 = BASE64.encode(&encrypted_data);

        let result = decrypt(&tampered_encrypted_b64, &priv_key, None);
        assert!(result.is_err());
    }
}
