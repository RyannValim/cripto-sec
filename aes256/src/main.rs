mod hmac_sha256;
mod pbkdf2;
mod aes;

use crate::pbkdf2::pbkdf2;
use crate::aes::{aes_encrypt, aes_decrypt};

use rand::rngs::OsRng;
use rand::RngCore;

fn main(){
    let password = b"Curitib@231";
    let c: u32 = 100_000;
    let dklen: u32 = 16;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let dk = pbkdf2(password, &salt, c, dklen);

    let plaintext = b"email@teste.com";
    let ciphertext = aes_encrypt(plaintext, &dk, dklen);
    let decrypted = aes_decrypt(&ciphertext, &dk, dklen);

    let hex: String = ciphertext.iter().map(|b| format!("{:02x}", b)).collect();

    println!("Chave secreta:\n{}", std::str::from_utf8(password).unwrap());
    println!("\nChave derivada com PBKDF2:\n{:?}", dk);
    println!("\nTexto de entrada:\n{}", std::str::from_utf8(plaintext).unwrap());
    println!("\nTexto encriptografado (hex):\n{}", hex);
    println!("\nTexto desencriptografado:\n{}", String::from_utf8(decrypted).unwrap());
}