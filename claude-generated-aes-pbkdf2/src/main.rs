// ============================================================
// main.rs — ponto de entrada e demonstração integrada
// ============================================================
//
// Este arquivo amarra os três módulos:
//   sha256  → função de hash base
//   pbkdf2  → deriva uma chave forte a partir de uma senha
//   aes     → cifra/decifra dados com a chave derivada
//
// Fluxo completo:
//   senha + salt → PBKDF2-HMAC-SHA256 → chave AES de 16 bytes
//   plaintext + chave + IV → AES-CBC → ciphertext
//   ciphertext + chave + IV → AES-CBC-decrypt → plaintext original
// ============================================================

mod aes;
mod pbkdf2;
mod sha256;

fn main() {
    println!("=================================================");
    println!("  AES-128-CBC + PBKDF2-HMAC-SHA256 — demo");
    println!("=================================================\n");

    // --------------------------------------------------------
    // Etapa 1: Definir os parâmetros de entrada
    // --------------------------------------------------------

    // A senha que o usuário forneceria em uma aplicação real.
    // Pode ser curta, fraca, com espaços — o PBKDF2 lida com tudo isso.
    let password = b"minha_senha_secreta";

    // O salt é gerado aleatoriamente no momento do cadastro/criptografia
    // e armazenado junto ao ciphertext. Nunca deve se repetir.
    // Em produção, use um CSPRNG (ex: rand::rngs::OsRng no Rust).
    // Aqui usamos um valor fixo para o resultado ser reproduzível.
    let salt = b"\xa3\xf8\xc2\xd1\xe4\xb0\x92\x71\x5f\x3e\x8a\x1c\x60\xd9\x47\x2b";

    // O IV (Initialization Vector) é gerado aleatoriamente a cada
    // operação de cifragem e também armazenado junto ao ciphertext.
    // Nunca reutilize o mesmo IV com a mesma chave!
    let iv: [u8; 16] = [
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
        0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
    ];

    // O número de iterações determina o custo de força bruta.
    // 100.000 é o mínimo recomendado pelo OWASP em 2024.
    // Aqui usamos 1.000 para a demo terminar rapidamente.
    let iterations = 1_000u32;

    // O plaintext que queremos proteger
    let plaintext = b"eusouoryannvalim"; // exatamente 16 bytes — um bloco AES

    println!("[entrada]");
    println!("  senha     : {}", std::str::from_utf8(password).unwrap());
    println!("  plaintext : {}", std::str::from_utf8(plaintext).unwrap());
    println!("  iterações : {}\n", iterations);

    // --------------------------------------------------------
    // Etapa 2: Derivar a chave com PBKDF2
    // --------------------------------------------------------
    //
    // O PBKDF2 transforma a senha fraca em 16 bytes de chave AES.
    // dk_len = 16 porque estamos usando AES-128 (128 bits = 16 bytes).
    // Para AES-256, use dk_len = 32.

    let aes_key_vec = pbkdf2::pbkdf2_hmac_sha256(password, salt, iterations, 16);
    let aes_key: [u8; 16] = aes_key_vec.try_into().expect("PBKDF2 deve retornar 16 bytes");

    println!("[PBKDF2]");
    println!("  chave derivada : {}", hex(&aes_key));
    println!("  (16 bytes prontos para o AES-128)\n");

    // --------------------------------------------------------
    // Etapa 3: Cifrar com AES-128-CBC
    // --------------------------------------------------------

    let ciphertext = aes::aes_cbc_encrypt(plaintext, &aes_key, &iv);

    println!("[AES-128-CBC encrypt]");
    println!("  IV         : {}", hex(&iv));
    println!("  ciphertext : {}\n", hex(&ciphertext));

    // --------------------------------------------------------
    // Etapa 4: Decifrar — reproduz o plaintext original
    // --------------------------------------------------------
    //
    // Para decifrar, o receptor precisa de:
    //   1. A senha (segredo compartilhado — nunca transmitida)
    //   2. O salt (transmitido junto ao ciphertext)
    //   3. O IV  (transmitido junto ao ciphertext)
    //   4. O ciphertext em si
    //
    // Com esses quatro elementos, refaz o PBKDF2 e decifra.

    let decrypted = aes::aes_cbc_decrypt(&ciphertext, &aes_key, &iv);

    println!("[AES-128-CBC decrypt]");
    println!("  plaintext recuperado : {}", std::str::from_utf8(&decrypted).unwrap());

    // Verifica que o round-trip foi perfeito
    assert_eq!(plaintext.as_ref(), decrypted.as_slice(), "round-trip falhou!");
    println!("\n  round-trip OK — encrypt/decrypt produz o plaintext original\n");

    // --------------------------------------------------------
    // Etapa 5: Validação com vetor oficial do NIST
    // --------------------------------------------------------
    //
    // O NIST publicou vetores de teste para o AES (FIPS 197, Apêndice B).
    // Se nossa implementação produzir exatamente os mesmos bytes,
    // sabemos que está correta.
    //
    // Vetor NIST AES-128 ECB:
    //   Plaintext : 3243f6a8885a308d313198a2e0370734
    //   Key       : 2b7e151628aed2a6abf7158809cf4f3c
    //   Expected  : 3925841d02dc09fbdc118597196a0b32

    println!("=================================================");
    println!("  Validação com vetor oficial NIST (FIPS 197)");
    println!("=================================================\n");

    let nist_plain: [u8; 16] = [
        0x32,0x43,0xf6,0xa8, 0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2, 0xe0,0x37,0x07,0x34,
    ];
    let nist_key: [u8; 16] = [
        0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c,
    ];
    let nist_expected: [u8; 16] = [
        0x39,0x25,0x84,0x1d, 0x02,0xdc,0x09,0xfb,
        0xdc,0x11,0x85,0x97, 0x19,0x6a,0x0b,0x32,
    ];

    let nist_result = aes::aes_encrypt_block(&nist_plain, &nist_key);

    println!("  plaintext  : {}", hex(&nist_plain));
    println!("  chave      : {}", hex(&nist_key));
    println!("  esperado   : {}", hex(&nist_expected));
    println!("  obtido     : {}", hex(&nist_result));

    if nist_result == nist_expected {
        println!("\n  NIST OK — implementação AES correta\n");
    } else {
        println!("\n  NIST FALHOU — verifique a implementação\n");
    }

    // --------------------------------------------------------
    // Etapa 6: Demonstração do State (column-major)
    // --------------------------------------------------------
    //
    // Mostra visualmente como os 16 bytes do plaintext
    // são dispostos na matriz 4×4 do AES.

    println!("=================================================");
    println!("  Visualização do State (column-major)");
    println!("=================================================\n");

    let demo_input = b"eusouoryannvalim";
    let state = aes::bytes_to_state(demo_input);

    println!("  input: \"{}\"", std::str::from_utf8(demo_input).unwrap());
    println!("  bytes: {}\n", hex(demo_input));
    println!("  State 4×4 (cada célula = 1 byte em hex):\n");
    println!("       col0  col1  col2  col3");
    for (i, row) in state.iter().enumerate() {
        print!("  row{i}  ");
        for byte in row {
            print!(" {:02x}  ", byte);
        }
        println!();
    }
    println!();
    println!("  Confirma column-major:");
    println!("    state[0][0]='e'={:02x}  state[1][0]='u'={:02x}",
        state[0][0], state[1][0]);
    println!("    state[2][0]='s'={:02x}  state[3][0]='o'={:02x}",
        state[2][0], state[3][0]);
}

// Converte bytes para string hexadecimal para exibição
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}
