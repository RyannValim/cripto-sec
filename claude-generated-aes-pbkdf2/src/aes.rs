// ============================================================
// AES-128 — implementação do zero para fins de estudo
// ============================================================
//
// AES (Advanced Encryption Standard) é uma cifra de bloco
// simétrica padronizada pelo NIST em 2001 (FIPS 197).
// "Simétrica" significa que a mesma chave cifra e decifra.
// "Cifra de bloco" significa que opera em blocos de tamanho fixo:
// sempre 128 bits (16 bytes) por vez.
//
// Esta implementação cobre AES-128 (chave de 128 bits, 10 rounds).
// AES-192 e AES-256 seguem a mesma estrutura com mais rounds
// e key schedule ligeiramente diferente.
//
// Estrutura de um round completo (exceto o último):
//   SubBytes   — substituição não-linear byte a byte via S-Box
//   ShiftRows  — permutação cíclica das linhas da matriz State
//   MixColumns — mistura linear das colunas via GF(2⁸)
//   AddRoundKey — XOR do State com a round key derivada
//
// O último round omite MixColumns (por razões de simetria
// matemática que facilitam a inversão/decriptação).
// ============================================================

// ============================================================
// S-Box (Substitution Box)
// ============================================================
//
// A S-Box é uma tabela de 256 entradas usada pelo SubBytes.
// Cada byte do State é substituído pelo valor na posição
// correspondente da S-Box.
//
// Como a S-Box foi construída (não precisa memorizar, só entender):
//   1. Para cada byte b, calcula o inverso multiplicativo em GF(2⁸).
//      (O inverso de 0x00 é definido como 0x00 por convenção.)
//   2. Aplica uma transformação afim sobre os bits do resultado.
//
// Por que isso garante segurança?
//   - A inversão em GF(2⁸) é altamente não-linear. Isso quebra
//     padrões que ataques algébricos poderiam explorar.
//   - Sem não-linearidade, o AES seria apenas XORs e shifts
//     — quebrável por álgebra linear.
#[rustfmt::skip]
pub const S_BOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

// S-Box inversa — usada na decriptação (SubBytes invertido)
#[rustfmt::skip]
pub const S_BOX_INV: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

// ============================================================
// Tipo State
// ============================================================
//
// O "State" é a matriz 4×4 de bytes sobre a qual o AES opera.
// Indexação: state[linha][coluna]
//
// ATENÇÃO: os bytes do plaintext são preenchidos em column-major:
//   state[0][0] state[0][1] state[0][2] state[0][3]
//     byte[0]    byte[4]    byte[8]    byte[12]
//   state[1][0] state[1][1] state[1][2] state[1][3]
//     byte[1]    byte[5]    byte[9]    byte[13]
//   ... e assim por diante.
pub type State = [[u8; 4]; 4];

// Converte 16 bytes em State (column-major)
pub fn bytes_to_state(input: &[u8; 16]) -> State {
    let mut state = [[0u8; 4]; 4];
    for col in 0..4 {
        for row in 0..4 {
            // O byte na posição `col*4 + row` vai para state[row][col]
            state[row][col] = input[col * 4 + row];
        }
    }
    state
}

// Converte State de volta em 16 bytes (column-major)
pub fn state_to_bytes(state: &State) -> [u8; 16] {
    let mut output = [0u8; 16];
    for col in 0..4 {
        for row in 0..4 {
            output[col * 4 + row] = state[row][col];
        }
    }
    output
}

// ============================================================
// Operação 1: SubBytes
// ============================================================
//
// Substitui cada byte do State pelo valor correspondente na S-Box.
// É a única operação não-linear do AES — sem ela, o algoritmo
// inteiro seria quebrável por álgebra linear simples.
//
// Exemplo: se state[1][2] = 0xEA, ele vira S_BOX[0xEA] = 0x87.
pub fn sub_bytes(state: &mut State) {
    for row in state.iter_mut() {
        for byte in row.iter_mut() {
            *byte = S_BOX[*byte as usize];
        }
    }
}

// SubBytes inverso — usa a S-Box inversa na decriptação
pub fn sub_bytes_inv(state: &mut State) {
    for row in state.iter_mut() {
        for byte in row.iter_mut() {
            *byte = S_BOX_INV[*byte as usize];
        }
    }
}

// ============================================================
// Operação 2: ShiftRows
// ============================================================
//
// Desloca ciclicamente cada linha do State para a esquerda:
//   linha 0: sem deslocamento      [a b c d] → [a b c d]
//   linha 1: desloca 1 byte        [a b c d] → [b c d a]
//   linha 2: desloca 2 bytes       [a b c d] → [c d a b]
//   linha 3: desloca 3 bytes       [a b c d] → [d a b c]
//
// Por que isso importa?
// ShiftRows garante que bytes de diferentes colunas se misturem
// em rounds subsequentes. Sem ShiftRows, cada coluna seria
// processada de forma completamente independente — seria como
// ter quatro cifras separadas de 32 bits, muito mais fracas.
pub fn shift_rows(state: &mut State) {
    // Linha 0: sem deslocamento — não faz nada

    // Linha 1: rotação de 1 para a esquerda
    state[1].rotate_left(1);

    // Linha 2: rotação de 2 para a esquerda
    state[2].rotate_left(2);

    // Linha 3: rotação de 3 para a esquerda (= 1 para a direita)
    state[3].rotate_left(3);
}

// ShiftRows inverso — desloca para a direita na decriptação
pub fn shift_rows_inv(state: &mut State) {
    state[1].rotate_right(1);
    state[2].rotate_right(2);
    state[3].rotate_right(3);
}

// ============================================================
// Multiplicação em GF(2⁸) — base para MixColumns
// ============================================================
//
// GF(2⁸) é um campo finito (Galois Field) com 256 elementos.
// Todos os cálculos são feitos em módulo do polinômio irredutível:
//   x⁸ + x⁴ + x³ + x + 1  (= 0x11b em binário)
//
// A multiplicação em GF(2⁸) NÃO é a multiplicação normal de inteiros!
// É uma multiplicação de polinômios com coeficientes em GF(2) (0 ou 1),
// reduzidos módulo 0x11b.
//
// xtime(b) = multiplica b por 2 (por x) em GF(2⁸):
//   - Shift left de 1 bit (multiplicar por x)
//   - Se o bit mais significante era 1, XOR com 0x1b (redução modular)
//     (0x1b = 0x11b sem o bit de overflow, os 8 bits baixos do polinômio)
#[inline]
fn xtime(b: u8) -> u8 {
    // Se o bit 7 está setado, vai "transbordar" após o shift
    // e precisamos reduzir módulo 0x11b.
    (b << 1) ^ (if b & 0x80 != 0 { 0x1b } else { 0x00 })
}

// Multiplicação genérica em GF(2⁸) usando o método "multiply by doubling".
// Decompõe o multiplicador em potências de 2 e usa xtime iterativamente.
#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    while b > 0 {
        // Se o bit menos significante de b é 1, adiciona `a` ao resultado
        // (adição em GF(2) = XOR)
        if b & 1 != 0 {
            result ^= a;
        }
        a = xtime(a); // dobra `a` (multiplica por x)
        b >>= 1;       // avança para o próximo bit de b
    }
    result
}

// ============================================================
// Operação 3: MixColumns
// ============================================================
//
// Trata cada coluna do State como um polinômio de 4 termos
// com coeficientes em GF(2⁸) e multiplica pela matrix fixa:
//
//   | 2 3 1 1 |
//   | 1 2 3 1 |
//   | 1 1 2 3 |
//   | 3 1 1 2 |
//
// Cada byte da nova coluna é calculado como combinação linear
// dos quatro bytes da coluna original, usando multiplicação em GF(2⁸).
//
// Por que isso importa?
// MixColumns garante que cada byte de saída dependa de todos os 4
// bytes de entrada da mesma coluna. Combinado com ShiftRows (que
// distribui bytes entre colunas), após 2 rounds cada byte de saída
// depende de todos os 16 bytes de entrada — é o "efeito avalanche"
// completo do AES, conhecido como o critério SAC.
pub fn mix_columns(state: &mut State) {
    for col in 0..4 {
        let s0 = state[0][col];
        let s1 = state[1][col];
        let s2 = state[2][col];
        let s3 = state[3][col];

        // Multiplicação pela matriz fixa do MixColumns
        state[0][col] = gf_mul(2, s0) ^ gf_mul(3, s1) ^ s2           ^ s3;
        state[1][col] = s0           ^ gf_mul(2, s1) ^ gf_mul(3, s2) ^ s3;
        state[2][col] = s0           ^ s1           ^ gf_mul(2, s2) ^ gf_mul(3, s3);
        state[3][col] = gf_mul(3, s0) ^ s1           ^ s2           ^ gf_mul(2, s3);
    }
}

// MixColumns inverso — usa a matriz inversa na decriptação:
//   | 14  11  13   9 |
//   |  9  14  11  13 |
//   | 13   9  14  11 |
//   | 11  13   9  14 |
pub fn mix_columns_inv(state: &mut State) {
    for col in 0..4 {
        let s0 = state[0][col];
        let s1 = state[1][col];
        let s2 = state[2][col];
        let s3 = state[3][col];

        state[0][col] = gf_mul(14,s0) ^ gf_mul(11,s1) ^ gf_mul(13,s2) ^ gf_mul( 9,s3);
        state[1][col] = gf_mul( 9,s0) ^ gf_mul(14,s1) ^ gf_mul(11,s2) ^ gf_mul(13,s3);
        state[2][col] = gf_mul(13,s0) ^ gf_mul( 9,s1) ^ gf_mul(14,s2) ^ gf_mul(11,s3);
        state[3][col] = gf_mul(11,s0) ^ gf_mul(13,s1) ^ gf_mul( 9,s2) ^ gf_mul(14,s3);
    }
}

// ============================================================
// Operação 4: AddRoundKey
// ============================================================
//
// É a operação mais simples do AES: XOR byte a byte entre o State
// e a round key correspondente ao round atual.
//
// Por que XOR?
//   - XOR é a "adição" em GF(2): reversível, sem carry, sem padrão.
//   - Sem a chave, é impossível desfazer o XOR.
//   - Com a chave, desfazer é trivial: basta fazer XOR novamente
//     (pois A ⊕ K ⊕ K = A).
//
// Esta operação aparece:
//   - Uma vez antes do primeiro round (whitening inicial)
//   - Uma vez no final de cada round completo
//
// A round_key tem o mesmo formato do State: [[u8; 4]; 4]
pub fn add_round_key(state: &mut State, round_key: &State) {
    for row in 0..4 {
        for col in 0..4 {
            state[row][col] ^= round_key[row][col];
        }
    }
}

// ============================================================
// Key Schedule (Expansão de Chave)
// ============================================================
//
// O AES-128 recebe uma chave de 16 bytes, mas precisa de uma
// round key diferente para cada um dos 10 rounds + 1 inicial.
// Total: 11 round keys × 16 bytes = 176 bytes.
//
// O Key Schedule expande a chave original em 11 round keys usando:
//   - RotWord: rotação de 1 byte para a esquerda em um word de 4 bytes
//   - SubWord: aplica a S-Box em cada byte do word
//   - Rcon: constante de round (potências de 2 em GF(2⁸))
//
// Rcon[i] = [x^(i-1), 0, 0, 0] em GF(2⁸), começando em i=1.
// Os valores são pré-calculados aqui para clareza.
const RCON: [u8; 11] = [
    0x00, // não usado (índice 0)
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36,
];

// Expande a chave de 16 bytes em 11 round keys.
// Retorna um array de 11 States, onde key_schedule[0] é o AddRoundKey
// inicial e key_schedule[i] é a round key do round i.
pub fn key_expansion(key: &[u8; 16]) -> [State; 11] {
    // Trabalha com 44 "words" de 4 bytes cada (11 round keys × 4 colunas)
    let mut w = [[0u8; 4]; 44];

    // Os primeiros 4 words vêm diretamente da chave original
    for i in 0..4 {
        w[i] = [key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]];
    }

    // Gera os words restantes
    for i in 4..44 {
        let mut temp = w[i - 1];

        if i % 4 == 0 {
            // A cada 4 words (início de nova round key):
            // 1. RotWord: rotação de 1 byte para a esquerda
            temp.rotate_left(1);
            // 2. SubWord: substitui cada byte pela S-Box
            for b in temp.iter_mut() {
                *b = S_BOX[*b as usize];
            }
            // 3. XOR com a constante de round (apenas no byte 0)
            temp[0] ^= RCON[i / 4];
        }

        // w[i] = w[i-4] XOR temp
        for j in 0..4 {
            w[i][j] = w[i - 4][j] ^ temp[j];
        }
    }

    // Converte os 44 words em 11 States (round keys)
    let mut round_keys = [[[0u8; 4]; 4]; 11];
    for rk in 0..11 {
        for col in 0..4 {
            for row in 0..4 {
                round_keys[rk][row][col] = w[rk * 4 + col][row];
            }
        }
    }
    round_keys
}

// ============================================================
// AES-128 Encrypt (modo ECB — um bloco)
// ============================================================
//
// Cifra um único bloco de 16 bytes com a chave fornecida.
//
// AVISO: ECB (Electronic Codebook) é o modo mais simples mas
// também o menos seguro para dados reais. Blocos iguais produzem
// ciphertexts iguais, revelando padrões. Em produção, use CBC ou GCM.
// Esta implementação é para fins didáticos.
pub fn aes_encrypt_block(plaintext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    // Expande a chave em 11 round keys
    let round_keys = key_expansion(key);

    // Carrega o plaintext no State (column-major)
    let mut state = bytes_to_state(plaintext);

    // ---- Round inicial: só AddRoundKey ----
    // "Whitening": XOR inicial com a chave antes de qualquer transformação.
    // Isso garante que o atacante não possa observar SubBytes sem conhecer a chave.
    add_round_key(&mut state, &round_keys[0]);

    // ---- Rounds 1 a 9: ciclo completo ----
    for round in 1..10 {
        sub_bytes(&mut state);    // substituição não-linear
        shift_rows(&mut state);   // permutação entre colunas
        mix_columns(&mut state);  // difusão dentro de cada coluna
        add_round_key(&mut state, &round_keys[round]); // mistura a chave
    }

    // ---- Round 10 (final): sem MixColumns ----
    // MixColumns é omitido no último round por razões de simetria:
    // isso torna a estrutura de encriptação e decriptação equivalentes,
    // simplificando implementações de hardware.
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[10]);

    // Converte o State final de volta para bytes
    state_to_bytes(&state)
}

// ============================================================
// AES-128 Decrypt (modo ECB — um bloco)
// ============================================================
//
// Decifra um único bloco de 16 bytes. Cada operação é invertida
// e aplicada na ordem inversa.
pub fn aes_decrypt_block(ciphertext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let round_keys = key_expansion(key);
    let mut state = bytes_to_state(ciphertext);

    // Round final invertido (era o último na encriptação)
    add_round_key(&mut state, &round_keys[10]);
    shift_rows_inv(&mut state);
    sub_bytes_inv(&mut state);

    // Rounds 9 a 1 invertidos
    for round in (1..10).rev() {
        add_round_key(&mut state, &round_keys[round]);
        mix_columns_inv(&mut state);
        shift_rows_inv(&mut state);
        sub_bytes_inv(&mut state);
    }

    // Round inicial invertido
    add_round_key(&mut state, &round_keys[0]);

    state_to_bytes(&state)
}

// ============================================================
// AES-CBC Encrypt
// ============================================================
//
// CBC (Cipher Block Chaining) é o modo de operação que torna o AES
// seguro para mensagens maiores que 16 bytes.
//
// Como funciona:
//   - O IV (Initialization Vector) é um bloco aleatório de 16 bytes.
//   - Antes de cifrar cada bloco, faz XOR com o ciphertext do bloco anterior.
//   - O primeiro bloco faz XOR com o IV.
//
//   C[0] = AES_enc( P[0] ⊕ IV )
//   C[i] = AES_enc( P[i] ⊕ C[i-1] )
//
// Resultado: dois blocos de plaintext idênticos produzem ciphertexts
// diferentes, pois o histórico anterior interfere em cada bloco.
//
// PKCS#7 Padding: se o plaintext não for múltiplo de 16 bytes,
// adiciona N bytes de valor N para completar o bloco. Se já for
// múltiplo, adiciona um bloco inteiro de 0x10.
pub fn aes_cbc_encrypt(plaintext: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    // Aplica PKCS#7 padding
    let pad_len = 16 - (plaintext.len() % 16);
    let mut padded = plaintext.to_vec();
    padded.extend(vec![pad_len as u8; pad_len]);

    let mut ciphertext = Vec::with_capacity(padded.len());
    let mut prev_block = *iv; // começa com o IV

    for chunk in padded.chunks(16) {
        // XOR do bloco atual com o bloco anterior (ou IV)
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev_block[i];
        }
        // Cifra o bloco resultante
        let encrypted = aes_encrypt_block(&block, key);
        ciphertext.extend_from_slice(&encrypted);
        prev_block = encrypted; // encadeia para o próximo bloco
    }

    ciphertext
}

// AES-CBC Decrypt
pub fn aes_cbc_decrypt(ciphertext: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev_block = *iv;

    for chunk in ciphertext.chunks(16) {
        let block: [u8; 16] = chunk.try_into().expect("bloco deve ter 16 bytes");
        // Decifra o bloco
        let decrypted = aes_decrypt_block(&block, key);
        // XOR com o bloco anterior para recuperar o plaintext
        for i in 0..16 {
            plaintext.push(decrypted[i] ^ prev_block[i]);
        }
        prev_block = block;
    }

    // Remove o PKCS#7 padding
    if let Some(&pad_len) = plaintext.last() {
        let pad_len = pad_len as usize;
        if pad_len <= 16 {
            plaintext.truncate(plaintext.len() - pad_len);
        }
    }

    plaintext
}
