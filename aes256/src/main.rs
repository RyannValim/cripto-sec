mod hmac_sha256;
mod pbkdf2;
mod aes;

use crate::pbkdf2::pbkdf2;
use crate::aes::aes;

use rand::rngs::OsRng;
use rand::RngCore;

fn main(){
    let password = b"Curitib@231";
    let c: u32 = 100_000;
    let dklen: u32 = 32;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let dk = pbkdf2(password, &salt, c, dklen);
    println!("\nDerived Key with PBKDF2:\n{:?}", dk);

    let plaintext = b"iryanngustavo@gmail.com";

    let ciphertext: Vec<u8> = aes(plaintext, &dk);
    println!("\nPlaintext: {:?}\nDerived key: {:?}\nCiphered text: {:?}", plaintext, dk, ciphertext);
}