use sha2::Sha256;
use hmac::{Hmac, Mac};
use rand::RngCore;

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256(senha: &[u8], mensagem: &[u8], salt: &[u8], c: u32) -> Vec<u8>{
  /*1. A derivação da chave ocorre em blocos:
      𝐷𝐾 = 𝑇1 ∣∣ 𝑇2 ∣∣. . . ∣∣ 𝑇𝑛

    2. Cada bloco 𝑇𝑖 é calculado assim:
      𝑇𝑖 = 𝑈1 ⊕ 𝑈2 ⊕. . .⊕ 𝑈𝑐
    
    3. Onde cada 𝑈 é calculado assim:
      𝑈1 = 𝐻(𝑃' 𝑆 ∣∣ 𝑖)
      𝑈2 = 𝐻(𝑃' 𝑈1)
      𝑈3 = 𝐻(𝑃' 𝑈2)
      𝑈𝑐 = 𝐻(𝑃' 𝑈𝑐−1)

      P = password
      s = salt
      i = block number
      h = função hash
  */

  // então eu preciso fazer no meu 𝑈1: mensagem = salt + numero_do_bloco  
  // agora preciso criar uma instância do hmac com a chave, passar a mensagem, finalizar e retornar os bytes
  let mut mac = HmacSha256::new_from_slice(senha)?; // ? = operador de propagação de erro (retorna o erro)
  let i: u32 = 1; // inicializa a variável de contagem de número do bloco.

  // montagem do vec<u8> para retorno -> S || i
  // aqui será concatenado (sem cálculos) os valores do salt e do número do bloco
  let mut mensagem = Vec::new();
  mensagem.extend_from_slice(salt);               // extend_from_slice() empurra os bytes de uma slice pro final do Vec
  mensagem.extend_from_slice(&i.to_be_bytes());   // to_be_bytes() converte u32 em 4 bytes na ordem "big-endian"

  // update e finalize
  for i in 0..=c{
    
  }

  return mensagem  
}

fn main(){
  let mut salt = [0u8; 16]; // 16 bytes = 128 bits
  rand::rngs::OsRng.fill_bytes(&mut salt); // preenche os 16 bytes com números aleatórios gerados pelo sistema

  hmac_sha256("curitiba", salt)
}