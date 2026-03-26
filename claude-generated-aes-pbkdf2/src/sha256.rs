// ============================================================
// SHA-256 — implementação do zero para fins de estudo
// ============================================================
//
// SHA-256 é uma função de hash criptográfica da família SHA-2.
// Ela recebe uma mensagem de qualquer tamanho e produz um
// digest de exatamente 256 bits (32 bytes).
//
// Propriedades fundamentais:
//   1. Determinística  — mesma entrada → mesma saída, sempre.
//   2. Efeito avalanche — 1 bit diferente na entrada muda ~50% da saída.
//   3. Irreversível     — dado o hash, impossível recuperar a entrada.
//   4. Resistente a colisões — impossível (na prática) achar dois
//      inputs com o mesmo hash.
//
// Referência: FIPS 180-4
// ============================================================

// ---- Constantes K ----
// São as 64 constantes de round do SHA-256.
// Derivadas dos primeiros 64 números primos: cada K[i] é formado
// pelos primeiros 32 bits da parte fracionária de cbrt(primo[i]).
// Isso garante que os valores são "nada-no-meu-bolso" (nothing-up-my-sleeve),
// ou seja, não foram escolhidos maliciosamente.
#[rustfmt::skip]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// ---- Valores iniciais H ----
// Os oito valores de hash iniciais. Assim como K, são derivados
// dos primeiros 8 primos: cada H[i] são os primeiros 32 bits
// da parte fracionária de sqrt(primo[i]).
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// ============================================================
// Funções auxiliares do SHA-256
// Todas operam em u32 com aritmética modular (wrapping_add).
// ============================================================

// Rotação circular à direita de `n` bits.
// Diferente do shift normal, os bits que "saem" pela direita
// reaparecem pela esquerda.
#[inline]
fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

// Σ0 (Sigma maiúsculo 0) — usada no cálculo do "majority"
#[inline]
fn big_sigma0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

// Σ1 (Sigma maiúsculo 1) — usada no cálculo do "choice"
#[inline]
fn big_sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

// σ0 (sigma minúsculo 0) — usada na expansão da message schedule
#[inline]
fn small_sigma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

// σ1 (sigma minúsculo 1) — usada na expansão da message schedule
#[inline]
fn small_sigma1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

// Ch (choice): para cada bit, escolhe entre y ou z baseado em x.
// Se bit de x = 1, pega o bit de y. Se = 0, pega o bit de z.
#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

// Maj (majority): para cada bit, retorna o valor da maioria (2 ou 3 uns).
#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

// ============================================================
// Pré-processamento (padding)
// ============================================================
//
// O SHA-256 processa blocos de 512 bits (64 bytes) por vez.
// Se a mensagem não for múltiplo de 512 bits, precisamos
// adicionar padding:
//
//   1. Append bit '1'  (= byte 0x80)
//   2. Append zeros até que len ≡ 448 (mod 512)
//   3. Append comprimento original da mensagem em 64 bits big-endian
//
// Isso garante que qualquer mensagem seja processada em blocos exatos.
fn pad(msg: &[u8]) -> Vec<u8> {
    let len_bits = (msg.len() as u64) * 8; // comprimento em bits

    let mut padded = msg.to_vec();
    padded.push(0x80); // bit '1' seguido de zeros (em um byte)

    // Adiciona zeros até que o comprimento em bytes ≡ 56 (mod 64)
    // (equivalente a 448 mod 512 em bits)
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }

    // Appenda o comprimento original como u64 big-endian (8 bytes)
    padded.extend_from_slice(&len_bits.to_be_bytes());

    padded
}

// ============================================================
// Função principal: sha256
// ============================================================
//
// Retorna os 32 bytes (256 bits) do digest.
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let padded = pad(msg);

    // Estado do hash — começa com os valores iniciais H
    let mut h = H_INIT;

    // Processa cada bloco de 64 bytes
    for block in padded.chunks(64) {
        // ---- Message Schedule (W) ----
        // Expande os 16 words do bloco em 64 words.
        // Os primeiros 16 vêm diretamente do bloco (big-endian).
        // Os demais são derivados dos anteriores usando σ0 e σ1.
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            w[i] = small_sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(small_sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        // ---- Variáveis de trabalho ----
        // Copia o estado atual para trabalhar sem modificar h ainda.
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        // ---- 64 rounds de compressão ----
        for i in 0..64 {
            let t1 = hh
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);

            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

            // Rotaciona as variáveis de trabalho
            hh = g;
            g  = f;
            f  = e;
            e  = d.wrapping_add(t1);
            d  = c;
            c  = b;
            b  = a;
            a  = t1.wrapping_add(t2);
        }

        // ---- Adiciona o resultado comprimido ao estado ----
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    // ---- Produz o digest final ----
    // Concatena os 8 words de 32 bits em 32 bytes big-endian.
    let mut digest = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}
