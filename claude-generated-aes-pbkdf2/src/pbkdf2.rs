// ============================================================
// PBKDF2-HMAC-SHA256 — implementação do zero para fins de estudo
// ============================================================
//
// PBKDF2 (Password-Based Key Derivation Function 2) é definido
// na RFC 2898 / PKCS#5. Seu objetivo é transformar uma senha
// humana (fraca, curta, previsível) em uma chave criptográfica
// forte o suficiente para ser usada em algoritmos como o AES.
//
// Ele resolve três problemas ao mesmo tempo:
//   1. Tamanho   — senha pode ter qualquer tamanho; a chave terá
//                  exatamente o tamanho que o AES precisa.
//   2. Entropia  — o processo distribui a entropia da senha
//                  uniformemente pelos bits da chave.
//   3. Custo     — iterações tornam força bruta computacionalmente
//                  cara para o atacante, sem incomodar o usuário.
//
// Estrutura:
//   PBKDF2 usa HMAC como sua PRF (Pseudo-Random Function).
//   O HMAC por sua vez usa SHA-256 internamente.
//   Então a cadeia é: Senha → HMAC-SHA256 (N vezes) → Chave AES
// ============================================================

use crate::sha256::sha256;

// ============================================================
// HMAC-SHA256
// ============================================================
//
// HMAC (Hash-based Message Authentication Code) é uma construção
// que combina uma função de hash com uma chave secreta.
//
// A fórmula é:
//   HMAC(K, m) = SHA256( (K ⊕ opad) || SHA256( (K ⊕ ipad) || m ) )
//
// Por que dois hashes aninhados e não um simples SHA256(K || m)?
// Porque SHA256(K || m) é vulnerável ao "length extension attack":
// um atacante que conhece SHA256(K || m) consegue calcular
// SHA256(K || m || extra) sem conhecer K. O HMAC fecha essa brecha.
//
// ipad = 0x36 repetido (inner pad)
// opad = 0x5C repetido (outer pad)
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // O HMAC exige que a chave tenha exatamente o tamanho do bloco
    // do hash subjacente. Para SHA-256, o bloco tem 64 bytes.
    //   - Se a chave for maior que 64 bytes: faz hash dela primeiro.
    //   - Se for menor: preenche com zeros à direita.
    let mut k = [0u8; 64];
    if key.len() > 64 {
        // Chave longa: reduz com hash
        let hashed = sha256(key);
        k[..32].copy_from_slice(&hashed);
    } else {
        // Chave curta ou exata: copia e o resto fica como zero (padding)
        k[..key.len()].copy_from_slice(key);
    }

    // ---- Hash interno: SHA256( (K ⊕ ipad) || message ) ----
    // ipad = 0x36. XOR de cada byte da chave com 0x36.
    let mut inner = Vec::with_capacity(64 + message.len());
    for &byte in k.iter() {
        inner.push(byte ^ 0x36);
    }
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);

    // ---- Hash externo: SHA256( (K ⊕ opad) || inner_hash ) ----
    // opad = 0x5C. XOR de cada byte da chave com 0x5C.
    let mut outer = Vec::with_capacity(64 + 32);
    for &byte in k.iter() {
        outer.push(byte ^ 0x5c);
    }
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

// ============================================================
// PBKDF2-HMAC-SHA256
// ============================================================
//
// Parâmetros:
//   password   — a senha do usuário (bytes)
//   salt       — bytes aleatórios gerados no cadastro (nunca reutilizar!)
//   iterations — número de vezes que o HMAC será encadeado.
//                Recomendação OWASP 2024: mínimo 210.000 para PBKDF2-SHA256.
//   dk_len     — comprimento desejado da chave derivada em bytes.
//                Para AES-128: 16. Para AES-256: 32.
//
// Retorna um Vec<u8> com `dk_len` bytes prontos para uso como chave AES.
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dk_len: usize,
) -> Vec<u8> {
    // SHA-256 produz 32 bytes por bloco. Para gerar mais de 32 bytes
    // de chave, o PBKDF2 repete o processo em blocos numerados.
    // h_len = comprimento da saída do HMAC = 32 bytes para SHA-256.
    const H_LEN: usize = 32;

    // Quantos blocos precisamos para cobrir dk_len bytes?
    let num_blocks = dk_len.div_ceil(H_LEN);

    let mut derived_key = Vec::with_capacity(num_blocks * H_LEN);

    // Cada bloco i é calculado de forma independente e concatenado.
    for i in 1..=num_blocks {
        derived_key.extend_from_slice(&pbkdf2_block(password, salt, iterations, i as u32));
    }

    // Trunca ao tamanho exato pedido (o último bloco pode ser parcial)
    derived_key.truncate(dk_len);
    derived_key
}

// ============================================================
// Função auxiliar: calcula um bloco do PBKDF2
// ============================================================
//
// Esta é a engrenagem central do PBKDF2. Para o bloco de índice `i`:
//
//   U1 = HMAC(password, salt || i)       ← primeira iteração usa o salt
//   U2 = HMAC(password, U1)              ← as demais encadeiam o resultado anterior
//   U3 = HMAC(password, U2)
//   ...
//   Un = HMAC(password, U(n-1))
//
//   T_i = U1 ⊕ U2 ⊕ U3 ⊕ ... ⊕ Un
//
// O XOR final garante que mesmo que alguma iteração produza baixa
// entropia por acidente, as outras compensam no resultado.
// O custo para o atacante não muda: ele precisa calcular todos os U_n
// de qualquer forma.
fn pbkdf2_block(password: &[u8], salt: &[u8], iterations: u32, block_index: u32) -> [u8; 32] {
    // Monta a entrada da primeira iteração: salt concatenado com
    // o índice do bloco em big-endian (4 bytes).
    // O índice garante que blocos diferentes produzam saídas diferentes,
    // mesmo com o mesmo salt e senha.
    let mut input = Vec::with_capacity(salt.len() + 4);
    input.extend_from_slice(salt);
    input.extend_from_slice(&block_index.to_be_bytes());

    // U1 — primeira iteração
    let u1 = hmac_sha256(password, &input);

    // `result` acumula o XOR de todos os U_i.
    // Começa igual a U1.
    let mut result = u1;
    let mut prev = u1;

    // Itera de U2 até U_n, fazendo XOR acumulado
    for _ in 1..iterations {
        // U_n = HMAC(password, U_(n-1))
        let u_next = hmac_sha256(password, &prev);

        // XOR byte a byte do resultado acumulado
        for (r, &u) in result.iter_mut().zip(u_next.iter()) {
            *r ^= u;
        }

        prev = u_next;
    }

    result
}
