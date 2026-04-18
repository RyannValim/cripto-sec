mod hmac_sha256;
mod pbkdf2;
mod aes;

use crate::pbkdf2::pbkdf2;
use crate::aes::{aes_encrypt_cbc, aes_decrypt_cbc, aes_encrypt_cbc_teste_nist};

use rand::rngs::OsRng;
use rand::RngCore;

fn testar_nist() {
    let key: Vec<u8> = hex::decode(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    ).unwrap();

    let iv: [u8; 16] = hex::decode(
        "000102030405060708090a0b0c0d0e0f"
    ).unwrap().try_into().unwrap();

    let plaintext: Vec<u8> = hex::decode(
        "6bc1bee22e409f96e93d7e117393172a"
    ).unwrap();

    let expected: Vec<u8> = hex::decode(
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
    ).unwrap();

    let result = aes_encrypt_cbc_teste_nist(&plaintext, &key, 32, iv);

    if result == expected {
        println!("\nTeste do NIST: SUCESSO!");
    } else {
        println!("\nTeste do NIST: FALHA!");
        println!("Esperado: {}", hex::encode(&expected));
        println!("Obtido:   {}", hex::encode(&result));
    }
}

fn main(){
    let password = b"Curitib@231";
    let c: u32 = 100_000;
    let dklen: u32 = 32;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let dk = pbkdf2(password, &salt, c, dklen);

    let plaintext = b"email@teste.com";
    let iv_ciphertext = aes_encrypt_cbc(plaintext, &dk, dklen);
    let decrypted = aes_decrypt_cbc(&iv_ciphertext, &dk, dklen);

    let hex: String = iv_ciphertext.iter().map(|b| format!("{:02x}", b)).collect();

    println!("Chave secreta:\n{}", std::str::from_utf8(password).unwrap());
    println!("\nChave derivada com PBKDF2:\n{:?}", dk);
    println!("\nTexto de entrada:\n{}", std::str::from_utf8(plaintext).unwrap());
    println!("\nTexto encriptografado (hex):\n{}", hex);
    println!("\nTexto desencriptografado:\n{}", String::from_utf8(decrypted).unwrap());

    testar_nist();
}