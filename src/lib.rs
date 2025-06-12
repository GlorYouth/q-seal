pub mod traditional;
pub mod post_quantum;

#[cfg(test)]
mod tests {
    use super::{post_quantum, traditional};
    use rsa::rand_core::OsRng;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    #[test]
    fn test_traditional_full_flow() {
        let test_input = "Hello, traditional world!";
        let mut rng = OsRng;

        // 1. 生成自定义的密钥结构体
        let (pub_key_struct, priv_key_struct) =
            traditional::generate_keypair(&mut rng).unwrap();

        // 2. 从结构体重建 RSA 库所需的密钥对象
        let rsa_pub_key = RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&pub_key_struct.n),
            rsa::BigUint::from_bytes_be(&pub_key_struct.e),
        )
        .unwrap();

        let rsa_priv_key = RsaPrivateKey::from_components(
            rsa::BigUint::from_bytes_be(&pub_key_struct.n), // 使用公钥的n
            rsa::BigUint::from_bytes_be(&pub_key_struct.e), // 使用公钥的e
            rsa::BigUint::from_bytes_be(&priv_key_struct.d),
            vec![
                rsa::BigUint::from_bytes_be(&priv_key_struct.p),
                rsa::BigUint::from_bytes_be(&priv_key_struct.q),
            ],
        )
        .unwrap();

        // 3. 加密和解密
        let encrypted = traditional::encrypt(test_input, &rsa_pub_key, &mut rng).unwrap();
        let decrypted = traditional::decrypt(&encrypted, &rsa_priv_key).unwrap();

        // 4. 验证结果
        assert_eq!(test_input, decrypted);
    }

    #[test]
    fn test_post_quantum_full_flow() {
        let test_input = "Hello, post-quantum world!";
        let mut rng = rand::rng();

        // 1. 生成密钥
        let (pub_key, priv_key) = post_quantum::generate_keypair();

        // 2. 加密和解密
        let encrypted = post_quantum::encrypt(test_input, &pub_key, None, &mut rng).unwrap();
        let decrypted = post_quantum::decrypt(&encrypted, &priv_key, None).unwrap();

        // 3. 验证结果
        assert_eq!(test_input, decrypted);
    }
}
