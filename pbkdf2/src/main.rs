//Password-Based Key Derivation Function 2 - PBKDF2

/*
OBJETIVO:
 Criar um hash e atrasar propositalmente o processamento
 para frustrar ataques de força bruta ou dicionário.

ARQUITETURA:
 Entradas necessárias:
 -Password: o texto original inserido pelo usuário.
 -Salt: valor aleatório único gerado para aquele
  usuário (evita Rainbow Tables).
 -Iterações (c): número de vezes que o motor de hash
  será rodada (ex: 100.000 a 600.000)
 -Tamanho (dkLen): quantos bytes a chave final deve ter.
 -Motor de hash (PRF): a função pseudoaleatória base (HMAC-SHA256)

 Fluxo de processamento:
 1. Priemira passada (U1): o HMAC é acionado usando Password como chave.
  A mensagem processada é o Salt concatenado com um número de bloco
  (iniciando em 1). A saída é um bloco de 32 bytes (capacidade do SHA256).
 2. O Loop de Iterações (U2 até Uc): a saída exata do passo anterior (u1)
  entra novamente no HMAC como mensagem, sempre utilizando Password como
  chave. Isso se repete em cadeia pelo número exato de iterações (c).
 3. A Combinação (XOR): todos os resultados intermediários gerados
  (U1, U2, ..., Uc) são misturados bit a bit usando a operação lógica
  matemática XOR (^). O resultado único deste imenso XOR é o "Bloco 1"
  válido.
 4. Extensão (Concatenação): o SHA256 gera blocos de 32 bytes. Se você
  pedir uma chave final (dkLen) de 64 bytes, o algoritmo repete os passos
  1 a 3 inteiros, mas agora alterando o número do bloco inicial para 2
  (Salt + 2). No fim, ele junta (concatena) o Bloco 1 com o Bloco 2 para
  entregar os 64 bytes.
*/

fn main() {
    
}