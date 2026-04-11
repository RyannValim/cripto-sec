mod hmac_sha256;
mod pbkdf2;
mod aes;

use crate::pbkdf2::pbkdf2;
use crate::aes::aes;

use rand::rngs::OsRng;
use rand::RngCore;

fn pkcs7_pad(plaintext: &[u8]) -> Vec<u8>{
    let block_size = 16;
    let pad_len = block_size - (plaintext.len() % block_size);
    let mut padded = plaintext.to_vec();
    padded.extend(vec![pad_len as u8; pad_len]);
    padded
}

fn pkcs7_unpad(padded: &[u8]) -> Vec<u8>{
    let pad_len = *padded.last().unwrap() as usize;
    padded[..padded.len() - pad_len].to_vec()
}

fn main(){
    let password = b"Curitib@231";
    let c: u32 = 100_000;
    let dklen: u32 = 16;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let dk = pbkdf2(password, &salt, c, dklen);

    let plaintext = b"iryanngustavo@gmail.com";
    let padded_plaintext = pkcs7_pad(plaintext);

    let ciphertext: Vec<u8> = aes(&padded_plaintext, &dk, dklen);
    println!("\nTexto de entrada:\n{:?}\n\n
        Chave derivada com PBKDF2:\n{:?}\n\n
        Texto encriptado:\n{:?}",
        plaintext, dk, ciphertext);
}