use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::oaep::Oaep;
#[allow(unused_imports)]
use rsa::rand_core::{OsRng, RngCore, CryptoRngCore};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::error::Error as StdError;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use std::convert::TryFrom;

const BITS: usize = 2048;

#[derive(Debug)]
pub enum Error {
    Rsa(rsa::Error),
    Base64(base64::DecodeError),
    Utf8(std::string::FromUtf8Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rsa(e) => write!(f, "RSA aihwa: {}", e),
            Error::Base64(e) => write!(f, "Base64 aihwa: {}", e),
            Error::Utf8(e) => write!(f, "UTF-8 aihwa: {}", e),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Rsa(e) => Some(e),
            Error::Base64(e) => Some(e),
            Error::Utf8(e) => Some(e),
        }
    }
}

impl From<rsa::Error> for Error { fn from(e: rsa::Error) -> Self { Error::Rsa(e) } }
impl From<base64::DecodeError> for Error { fn from(e: base64::DecodeError) -> Self { Error::Base64(e) } }
impl From<std::string::FromUtf8Error> for Error { fn from(e: std::string::FromUtf8Error) -> Self { Error::Utf8(e) } }


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

impl From<&RsaPublicKey> for PublicKey {
    fn from(key: &RsaPublicKey) -> Self {
        Self {
            n: key.n().to_bytes_be(),
            e: key.e().to_bytes_be(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PrivateKey {
    // For simplicity, we are just storing the components.
    // In a real application, you'd use a standard format like PKCS#8.
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub d: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
}

impl From<&RsaPrivateKey> for PrivateKey {
    fn from(key: &RsaPrivateKey) -> Self {
        Self {
            n: key.n().to_bytes_be(),
            e: key.e().to_bytes_be(),
            d: key.d().to_bytes_be(),
            p: key.primes()[0].to_bytes_be(),
            q: key.primes()[1].to_bytes_be(),
        }
    }
}

impl TryFrom<&PrivateKey> for RsaPrivateKey {
    type Error = rsa::Error;

    fn try_from(pk_struct: &PrivateKey) -> Result<Self, Self::Error> {
        let n = rsa::BigUint::from_bytes_be(&pk_struct.n);
        let e = rsa::BigUint::from_bytes_be(&pk_struct.e);
        let d = rsa::BigUint::from_bytes_be(&pk_struct.d);
        let p = rsa::BigUint::from_bytes_be(&pk_struct.p);
        let q = rsa::BigUint::from_bytes_be(&pk_struct.q);
        
        RsaPrivateKey::from_components(n, e, d, vec![p, q])
    }
}

pub fn generate_keypair<R>(rng: &mut R) -> Result<(PublicKey, PrivateKey), Error>
where
    R: RngCore + CryptoRngCore,
{
    let priv_key = RsaPrivateKey::new(rng, BITS)?;
    let pub_key = RsaPublicKey::from(&priv_key);
    Ok((PublicKey::from(&pub_key), PrivateKey::from(&priv_key)))
}

pub fn encrypt<R>(
    input: &str,
    public_key: &RsaPublicKey,
    rng: &mut R
) -> Result<String, Error>
where
    R: RngCore + CryptoRngCore,
{
    let padding = Oaep::new::<Sha256>();
    let encrypted = public_key.encrypt(rng, padding, input.as_bytes())?;
    Ok(BASE64.encode(&encrypted))
}

pub fn decrypt(encrypted: &str, private_key: &RsaPrivateKey) -> Result<String, Error> {
    let encrypted_bytes = BASE64.decode(encrypted)?;
    let padding = Oaep::new::<Sha256>();
    let decrypted_bytes = private_key.decrypt(padding, &encrypted_bytes)?;
    let result = String::from_utf8(decrypted_bytes)?;
    Ok(result)
}

pub fn decrypt_with_key_struct(encrypted: &str, private_key: &PrivateKey) -> Result<String, Error> {
    let rsa_private_key = RsaPrivateKey::try_from(private_key)?;
    decrypt(encrypted, &rsa_private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = OsRng;
        let (pub_key_struct, priv_key_struct) = generate_keypair(&mut rng).unwrap();

        // Reconstruct keys from components
        let rsa_pub_key = RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&pub_key_struct.n),
            rsa::BigUint::from_bytes_be(&pub_key_struct.e)
        ).unwrap();
        
        let rsa_priv_key = RsaPrivateKey::from_components(
            rsa_pub_key.n().clone(),
            rsa_pub_key.e().clone(),
            rsa::BigUint::from_bytes_be(&priv_key_struct.d),
            vec![
                rsa::BigUint::from_bytes_be(&priv_key_struct.p),
                rsa::BigUint::from_bytes_be(&priv_key_struct.q)
            ],
        ).unwrap();

        let test_input = "Hello, world!";
        let encrypted = encrypt(test_input, &rsa_pub_key, &mut rng).unwrap();
        let decrypted = decrypt(&encrypted, &rsa_priv_key).unwrap();
        
        assert_eq!(test_input, decrypted);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let mut rng = OsRng;
        let (pub_key_struct, _) = generate_keypair(&mut rng).unwrap();
        let (wrong_pub_key_struct, wrong_priv_key_struct) = generate_keypair(&mut rng).unwrap();
        
        let rsa_pub_key = RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&pub_key_struct.n),
            rsa::BigUint::from_bytes_be(&pub_key_struct.e)
        ).unwrap();

        let wrong_rsa_priv_key = RsaPrivateKey::from_components(
            rsa::BigUint::from_bytes_be(&wrong_pub_key_struct.n),
            rsa::BigUint::from_bytes_be(&wrong_pub_key_struct.e),
            rsa::BigUint::from_bytes_be(&wrong_priv_key_struct.d),
            vec![
                rsa::BigUint::from_bytes_be(&wrong_priv_key_struct.p),
                rsa::BigUint::from_bytes_be(&wrong_priv_key_struct.q)
            ],
        ).unwrap();

        let test_input = "This should not be decryptable";
        let encrypted = encrypt(test_input, &rsa_pub_key, &mut rng).unwrap();
        let result = decrypt(&encrypted, &wrong_rsa_priv_key);
        
        assert!(result.is_err());
    }
} 