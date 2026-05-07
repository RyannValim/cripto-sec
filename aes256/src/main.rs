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

fn cifrar(caminho: &str) {
    // 1. ler o arquivo
    let plaintext = std::fs::read(caminho).expect("Erro ao ler o arquivo.");

    // 2. pedir senha
    let password_string = rpassword::prompt_password("Digite a senha para cifrar: ").expect("Erro ao ler a senha");
    let password = password_string.as_bytes();

    // 3. gerar salt
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // 4. derivar chave com pbkdf2
    let c: u32 = 100_000;
    let dklen: u32 = 32;
    let dk = pbkdf2(password, &salt, c, dklen);

    // 5. cifrar com aes_encrypt_cbc
    let iv_ciphertext = aes_encrypt_cbc(&plaintext, &dk, dklen);
    
    // 6. salvar [salt(16)] + [IV(16)] + [ciphertext] em arquivo.cifrado
    let caminho_cifrado = format!("{}.cifrado", caminho);

    let mut conteudo_final = Vec::new();
    conteudo_final.extend_from_slice(&salt);
    conteudo_final.extend_from_slice(&iv_ciphertext);

    std::fs::write(&caminho_cifrado, &conteudo_final).expect("Erro ao salvar o arquivo.");
    println!("Arquivo cifrado salvo em: {}", caminho_cifrado);
}

fn decifrar(caminho: &str) {
    // 1. ler o arquivo
    let conteudo = std::fs::read(caminho).expect("Erro ao ler o arquivo.");
    
    // 2. pedir senha
    let password_string = rpassword::prompt_password("Digite a senha para decifrar: ").expect("Erro ao ler a senha");
    let password = password_string.as_bytes();

    // 3. extrair salt dos primeiros 16 bytes
    let salt = &conteudo[0..16];

    // 4. o resto é IV + ciphertext - passa direto pro aes_decrypt_cbc
    let iv_ciphertext = &conteudo[16..];
    
    // 5. decifrar chave com pbkdf2
    let c: u32 = 100_000;
    let dklen: u32 = 32;
    let dk = pbkdf2(password, salt, c, dklen);
    
    // 6. exibir conteúdo
    let decrypted = aes_decrypt_cbc(iv_ciphertext, &dk, dklen);

    //7. exibir conteúdo
    let texto_limpo = String::from_utf8(decrypted).expect("Erro ao converter para texto.");
    println!("{}", texto_limpo.trim_end());
}

fn main(){
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2{
        println!("Uso: cargo run -- <comando> [arquivo]");
        return;
    }

    match args[1].as_str(){
        "testar" => testar_nist(),
        "cifrar" => {
            if args.len() < 3{
                return println!("Erro: Faltou o nome do arquivo.");
            }
            cifrar(&args[2])
        },
        "decifrar" => {
            if args.len() < 3 {
                return println!("Erro: Faltou o nome do arquivo.");
            }
            decifrar(&args[2])
        },
        _ => println!("Comando inválido. Use: cifrar, decifrar ou testar."),
    }
}