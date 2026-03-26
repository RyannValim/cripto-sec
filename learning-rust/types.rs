/* tipos de inteiro explícitos
 não existe int genérico, é preciso declarar o tamanho: */
fn main(){
    let x: u8 = 255;        // unsigned 8 bits (0..=255)
    let y: u32 = 1000;      // unsigned 32 bits
    let z: u64 = 99999;     // unsigned 64 bits
        
    println!("Unsigned 8 bits: {}\nUnsigned 32 bits: {}\nUnsigned 64 bits: {}", x, y, z);
}