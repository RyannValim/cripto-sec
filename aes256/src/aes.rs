/* key_expansion(): O AES não usa a chave diretamente em cada round, ele deriva
 várias subchaves a partir da chave original. Para AES-128 são 11 subchaves,
 cada uma de 16 bytes. Essa função pega sua chave e gera todas elas. 
*/
// S-BOX do AES: tabela de substituição fixa de 256 valores
const SBOX: [u8; 256] = [
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

// constantes de round: valor diferente para cada round para garantir unicidade das subchaves
const RCON: [u8; 11] = [ 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// substitui cada palavra usando a SBOX
fn sub_word(w: [u8; 4]) -> [u8; 4]{
    let mut result: [u8; 4] = [0u8; 4];

    result[0] = SBOX[w[0] as usize];
    result[1] = SBOX[w[1] as usize];
    result[2] = SBOX[w[2] as usize];
    result[3] = SBOX[w[3] as usize];

    result
}

// rotaciona os 4 bytes ciclicamente: [a, b, c, d] -> [b, c, d, a]
fn rotate_word(w: [u8; 4]) -> [u8; 4]{
    let mut result: [u8; 4] = [0u8; 4];
    result[0] = w[1];
    result[1] = w[2];
    result[2] = w[3];
    result[3] = w[0];

    result
}

// aplica (rotate + sub + XOR com RCON): transforma w3 para derivar w0 novo.
fn schedule_core(w: [u8; 4], i: usize) -> [u8; 4]{ // recebe i (numero do round) para saber qual RCON utilizar
    let mut result: [u8; 4] = sub_word(rotate_word(w));
    result[0] ^= RCON[i];
    
    result
}

// faz XOR byte a byte entre duas palavras de 4 bytes
fn xor_words(a: & [u8; 4], b: & [u8; 4]) -> [u8; 4]{
    let mut result: [u8; 4] = [0u8; 4];
    result[0] = a[0] ^ b[0];
    result[1] = a[1] ^ b[1];
    result[2] = a[2] ^ b[2];
    result[3] = a[3] ^ b[3];

    result
}
 // <- significa [[16 itens], [16 itens], [16 itens], [16 itens], [16 itens], [16 itens], [16 itens], [16 itens], [16 itens], [16 itens], [16 itens]]
pub fn key_expansion(key: &[u8]) -> [[u8; 16]; 11]{
    let mut matriz_saida = [[0u8; 16]; 11];
    
    matriz_saida[0].copy_from_slice(key);

    for i in 1..11{
        let anterior = matriz_saida[i - 1];

        let w0_anterior: &[u8; 4] = anterior[0..4].try_into().unwrap();
        let w1_anterior: &[u8; 4] = anterior[4..8].try_into().unwrap();
        let w2_anterior: &[u8; 4] = anterior[8..12].try_into().unwrap();
        let w3_anterior: &[u8; 4] = anterior[12..16].try_into().unwrap();

        let w0_novo = xor_words(w0_anterior, &schedule_core(*w3_anterior, i));
        let w1_novo = xor_words(w1_anterior, &w0_novo);
        let w2_novo = xor_words(w2_anterior, &w1_novo);
        let w3_novo = xor_words(w3_anterior, &w2_novo);

        matriz_saida[i][0..4].copy_from_slice(&w0_novo);
        matriz_saida[i][4..8].copy_from_slice(&w1_novo);
        matriz_saida[i][8..12].copy_from_slice(&w2_novo);
        matriz_saida[i][12..16].copy_from_slice(&w3_novo);
    }

    matriz_saida
}

/* bytes_to_state(): O AES não opera em bytes lineares — ele organiza os dados
 numa matriz 4x4 de bytes, chamada de state. Essa função pega seus 16 bytes de
 plaintext e os organiza nessa grade.
*/
pub fn bytes_to_state(plaintext: [u8; 16]) -> [[u8; 4]; 4]{
    let mut state: [[u8; 4]; 4] = [[0u8; 4]; 4];
    let mut i_ptxt = 0;

    // preenchendo a matriz "State" via Column-Major
    for lin in 0..4{
        for col in 0..4{
            state[col][lin] = plaintext[i_ptxt];
            i_ptxt += 1;
        }
    }

    state
}

/* add_round_key(): Faz XOR byte a byte entre o state atual e a subchave do
 round atual. É a única etapa que mistura a chave com os dados.
*/
pub fn add_round_key(state: [[u8; 4]; 4], subkey: &[u8; 16]) -> [[u8; 4]; 4]{
    let mut state = state;
    let mut i_sb = 0;
    for lin in 0..4{
        for col in 0..4{
            state[col][lin] = state[col][lin] ^ subkey[i_sb];
            i_sb += 1;
        }
    }
    
    state
}

/*sub_bytes(): Substitui cada byte do state por um valor correspondente numa
 tabela fixa chamada S-Box. É uma operação de confusão — embaralha os valores
 de forma não-linear.
*/
pub fn sub_bytes(state: [[u8; 4]; 4]) -> [[u8; 4]; 4]{
    let mut state = state;
    
    for lin in 0..4{
        for col in 0..4{
            state[col][lin] = SBOX[state[col][lin] as usize];
        }        
    }

    state
}

/* shift_rows(): Desloca as linhas da matriz state ciclicamente para a esquerda.
 A linha 0 não move, linha 1 desloca 1, linha 2 desloca 2, linha 3 desloca 3.
*/
pub fn shift_rows(state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    let mut state = state;

    for lin in 0..4 {
        let mut temp_array: [u8; 4] = [
            state[0][lin],
            state[1][lin],
            state[2][lin],
            state[3][lin],
        ];

        temp_array.rotate_left(lin);

        state[0][lin] = temp_array[0];
        state[1][lin] = temp_array[1];
        state[2][lin] = temp_array[2];
        state[3][lin] = temp_array[3];
    }

    state
}

/* mix_columns(): Opera em cada coluna da matriz, misturando os 4 bytes dela usando
 multiplicação em campo finito (GF(2⁸)). É a etapa de difusão — espalha a influência
 de cada byte por toda a coluna.
*/
// Multiplica por 2 em GF(2⁸)
fn gf_mul2(x: u8) -> u8 {
    if x & 0x80 != 0 {    // verifica se o bit 7 é 1
        (x << 1) ^ 0x1b   // desloca e reduz com o polinômio do AES
    } else {
        x << 1             // só desloca
    }
}

// Multiplica por 3 em GF(2⁸) — 3 = 2 + 1, então é gf_mul2 XOR com o próprio valor
fn gf_mul3(x: u8) -> u8 {
    gf_mul2(x) ^ x
}

pub fn mix_columns(state: [[u8; 4]; 4]) -> [[u8; 4]; 4]{
    let mut novo_state = [[0u8; 4]; 4];

    // x⁷ + x⁶ + x⁵ + x⁴ + x³ + x² + x¹ + 1 = Polinômio
    for col in 0..4{
        let col_atual = [
            state[col][0],
            state[col][1],
            state[col][2],
            state[col][3]
        ];

        novo_state[col][0] = gf_mul2(col_atual[0]) ^ gf_mul3(col_atual[1]) ^ col_atual[2] ^ col_atual[3];
        novo_state[col][1] = col_atual[0] ^ gf_mul2(col_atual[1]) ^ gf_mul3(col_atual[2]) ^ col_atual[3];
        novo_state[col][2] = col_atual[0] ^ col_atual[1] ^ gf_mul2(col_atual[2]) ^ gf_mul3(col_atual[3]);
        novo_state[col][3] = gf_mul3(col_atual[0]) ^ col_atual[1] ^ col_atual[2] ^ gf_mul2(col_atual[3]);
    }

    novo_state
}

pub fn aes(plaintext: &[u8], dk: &[u8]) -> Vec<u8>{
    /* 1° etapa:
        key_expansion()         - gera as subchaves
        bytes_to_state()        - organiza o plaintext na matriz 4x4
        add_round_key()         - feito no round 0 (antes de qualquer round)
    */
    // 1° etapa: preparação
    let subchaves = key_expansion(dk);
    let mut ciphertext: Vec<u8> = Vec::new();

    // processa cada bloco de 16 bytes
    for bloco in plaintext.chunks(16) {
        let mut state = bytes_to_state(bloco.try_into().unwrap());
        state = add_round_key(state, &subchaves[0]);

        for round in 1..10 {
            state = sub_bytes(state);
            state = shift_rows(state);
            state = mix_columns(state);
            state = add_round_key(state, &subchaves[round]);
        }

        state = sub_bytes(state);
        state = shift_rows(state);
        state = add_round_key(state, &subchaves[10]);

        for lin in 0..4 {
            for col in 0..4 {
                ciphertext.push(state[col][lin]);
            }
        }
    }

    ciphertext
}

/*
> key_expansion(key) — recebe a chave derivada, quebra em 11 subchaves de 16 bytes cada usando rotate,
 substituição pela S-Box e XOR com Rcon, e devolve uma matriz [[u8; 16]; 11] com todas as subchaves.

> bytes_to_state(plaintext) — recebe 16 bytes do plaintext e os organiza numa matriz 4x4 em ordem
 column-major, devolvendo o [[u8; 4]; 4] chamado de state.

> add_round_key(state, subkey) — recebe o state atual e uma subchave de 16 bytes, faz XOR byte a byte
 entre os dois, e devolve o state modificado. É a única etapa que mistura a chave com os dados.

> sub_bytes(state) — recebe o state e substitui cada byte pelo valor correspondente na S-Box, devolvendo 
 o state com os bytes embaralhados de forma não-linear.

> shift_rows(state) — recebe o state e rotaciona cada linha ciclicamente para a esquerda pelo número da
 linha (linha 0 não move, linha 1 move 1, etc.), devolvendo o state reorganizado.

> gf_mul2 / gf_mul3 — funções auxiliares do mix_columns que multiplicam um byte por 2 ou 3 em campo finito
 GF(2⁸) usando shift de bits e XOR com o polinômio 0x1b.
 
> mix_columns(state) — recebe o state e mistura cada coluna aplicando a matriz de mistura do AES via
 multiplicações em GF(2⁸), devolvendo o state com a difusão aplicada.

> aes(plaintext, dk) — recebe o plaintext e a chave derivada, executa o key_expansion, organiza o state com
 bytes_to_state, aplica add_round_key no round 0, depois em loop aplica sub_bytes → shift_rows → mix_columns
 → add_round_key por 9 rounds, e finaliza com sub_bytes → shift_rows → add_round_key sem o mix_columns,
 devolvendo o ciphertext como Vec<u8>.
*/