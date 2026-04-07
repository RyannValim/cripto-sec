use crate::pbkdf2::pbkdf2;

/* key_expansion(): O AES não usa a chave diretamente em cada round, ele deriva
 várias subchaves a partir da chave original. Para AES-128 são 11 subchaves,
 cada uma de 16 bytes. Essa função pega sua chave e gera todas elas. 
*/
pub fn key_expansion(){

}

/* bytes_to_state(): O AES não opera em bytes lineares — ele organiza os dados
 numa matriz 4x4 de bytes, chamada de state. Essa função pega seus 16 bytes de
 plaintext e os organiza nessa grade.
*/
pub fn bytes_to_state(){

}

/* add_round_key(): Faz XOR byte a byte entre o state atual e a subchave do
 round atual. É a única etapa que mistura a chave com os dados.
*/
pub fn add_round_key(){

}

/*sub_bytes(): Substitui cada byte do state por um valor correspondente numa
 tabela fixa chamada S-Box. É uma operação de confusão — embaralha os valores
 de forma não-linear.
*/
pub fn sub_bytes(){

}

/* shift_rows(): Desloca as linhas da matriz state ciclicamente para a esquerda.
 A linha 0 não move, linha 1 desloca 1, linha 2 desloca 2, linha 3 desloca 3.
*/
pub fn shift_rows(){

}

/* mix_columns(): Opera em cada coluna da matriz, misturando os 4 bytes dela usando
 multiplicação em campo finito (GF(2⁸)). É a etapa de difusão — espalha a influência
 de cada byte por toda a coluna.
*/
pub fn mix_columns(){

}

pub fn aes(plaintext: &[u8], dk: &[u8]) -> Vec<u8>{
    let mut ciphertext: Vec<u8> = Vec::new();

    // 1° etapa
    

    // 2° etapa


    // 3° etapa


    ciphertext
}

/*
1° etapa:
 key_expansion()         - gera as subchaves
 bytes_to_state()        - organiza o plaintext na matriz 4x4
 add_round_key()         - feito no round 0 (antes de qualquer round)

2° etapa:
 loop rounds 1..(limite-1):
     sub_bytes()
     shift_rows()
     mix_columns()
     add_round_key()     - dentro do loop

3° etapa:
 round final (limite):
     sub_bytes()
     shift_rows()
     add_round_key()     - sem mix_columns
*/