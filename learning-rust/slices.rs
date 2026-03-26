/* um slice é uma visão de um trecho de memória
 como um ponteiro + tamanho. É o tipo que é usado para receber
 bytes de qualquer fonte (array fixo, Vec, string, etc.)
*/
fn processa(entrada: &[u8]) { 
    println!("Entrada: {:?}", entrada); // precisa utilizar '{:?}'
}

/* o uso de "trait debug ({:?})" invoca o formatador de debug.
 ele ignora a estética e apenas cospe a representação estrutural
 dos dados na tela, o rust já fornece a implementação de debug
 por padrão para quase todas as coleções nativas.

*/

fn main(){
    processa(b"texto literal");
    processa(&vec![1, 2, 3]);
    processa(&[0u8; 16]); // array de 16 zeros
}