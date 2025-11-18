use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 生成 Ed25519 密钥对（EdDSA）
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // 2. 使用固定消息做一次签名，并验证
    let message = b"hello Ed25519!";
    let signature: Signature = signing_key.sign(message);
    verifying_key
        .verify(message, &signature)
        .expect("signature verification failed");
    println!("✅ signature checked with verifying key");

    // 3. 导出字节数组
    let sk_bytes = signing_key.to_bytes(); // 32 bytes
    let pk_bytes = verifying_key.to_bytes(); // 32 bytes
    let sig_bytes = signature.to_bytes(); // 64 bytes

    // 4. 写入二进制文件
    write_binary("ed25519_secret.key", &sk_bytes)?;
    write_binary("ed25519_public.key", &pk_bytes)?;

    // 5. Base64 编码，方便复制
    let sk_b64 = general_purpose::STANDARD.encode(sk_bytes);
    let pk_b64 = general_purpose::STANDARD.encode(pk_bytes);
    let sig_b64 = general_purpose::STANDARD.encode(sig_bytes);

    println!("Ed25519 keys generated (EdDSA, FIPS-approved).");
    println!("Public key  (32 bytes, Base64):\n{}\n", pk_b64);
    println!("Secret key  (32 bytes, Base64):\n{}\n", sk_b64);
    println!("Signature   (64 bytes, Base64):\n{}\n", sig_b64);

    Ok(())
}

fn write_binary(path: &str, data: &[u8]) -> std::io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(data)?;
    Ok(())
}
