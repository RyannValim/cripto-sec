/* cada valor tem um dono
 quando é passado um valor para uma função, por padrão ele é movido
 o dono anterior perde o acesso, para emprestar sem transferir,
 usar o '&' (e comercial). */
fn imprime(dados: &[u8]){ // recebe como referência, não move.
    println!("{:?}", dados);
}

fn main(){
    let senha = vec![1u8, 2, 3];
    imprime(&senha); // empresta utilizando o '&'
    imprime(&senha); // ainda pode ser utilizado.
}