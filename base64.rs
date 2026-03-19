fn encode(input: &str, alfabeto: &[u8]) -> String {
    let bytes = input.as_bytes();
    let mut conversao = String::from("");

    for chunk in bytes.chunks(3){
        //Dividindo em chunks de 3, para facilitar o uso dos 24 bits
        // println!("[DBG] Bytes em chunks de 3: {:?}", chunk);

        //Salvando os bytes de entrada em variáveis auxiliares e checando a quantidade de paddings
        let mut total_paddings = 0;

        let byte0 = chunk[0];
        let byte1;
        let byte2;

        if chunk.len() > 1{
            byte1 = chunk[1];
        } else {
            byte1 = 0;
            total_paddings = 2;
        }

        if chunk.len() > 2{
            byte2 = chunk[2];
        } else{
            byte2 = 0;
            if total_paddings == 0{
                total_paddings = 1;
            }
        }

        //Juntando os bits da string, porém em decimal (binário para o sistema)
        let juncao_dos_bytes: u32 = ((byte0 as u32) << 16)
            | ((byte1 as u32) << 8)
            | (byte2 as u32);
        // println!("[DBG] Bits totais unidos: {}", juncao_dos_bytes);

        //Extração em grupos de 6
        let grupo1 = (juncao_dos_bytes >> 18) & 0x3F;
        let grupo2 = (juncao_dos_bytes >> 12) & 0x3F;
        let grupo3 = (juncao_dos_bytes >> 6) & 0x3F;
        let grupo4 = (juncao_dos_bytes >> 0) & 0x3F;

        // println!("[DBG] Grupos separados em seis bits: {} {} {} {}", grupo1, grupo2, grupo3, grupo4);

        conversao.push(alfabeto[grupo1 as usize] as char);
        conversao.push(alfabeto[grupo2 as usize] as char);

        if total_paddings == 2{
            conversao.push_str("==");
        } else if total_paddings == 1{
            conversao.push(alfabeto[grupo3 as usize] as char);
            conversao.push_str("=");
        } else{
            conversao.push(alfabeto[grupo3 as usize] as char);
            conversao.push(alfabeto[grupo4 as usize] as char);
        }
    }

    conversao // Sem o uso de ';' é considerado um retorno.
}

fn decode(encoded: &str, alfabeto: &[u8]) -> String{
    /*
      "para cada caractere da entrada Base64, acha o índice dele no alfabeto".
    */
    let mut padding_count = 0;
    let mut list_of_indexes: Vec<usize> = Vec::new();

    for char in encoded.chars(){
        if char != '='{
            let index = alfabeto.iter().position(|&x| x == char as u8).unwrap();
            list_of_indexes.push(index);
        } else {
            padding_count += 1;
        }
    }

    let mut conversao = String::new();

    for chunk in list_of_indexes.chunks(4){
        let i0 = chunk[0] as u32;
        let i1 = chunk[1] as u32;
        let i2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let i3 = if chunk.len() > 3 { chunk[3] as u32 } else { 0 };

        //Reconstrução dos 24 bits a partir dos 4 grupos de 6 bits
        let juncao: u32 = (i0 << 18) | (i1 << 12) | (i2 << 6) | (i3 << 0);

        //Extração dos bytes originais — inverso do encode
        let byte0 = (juncao >> 16) & 0xFF;
        let byte1 = (juncao >> 8) & 0xFF;
        let byte2 = (juncao >> 0) & 0xFF;

        conversao.push(byte0 as u8 as char);
        if chunk.len() > 2 { conversao.push(byte1 as u8 as char); }
        if chunk.len() > 3 { conversao.push(byte2 as u8 as char); }
    }

    conversao
}

fn main(){
    let alfabeto_base64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let string = String::from("curitiba");
    println!("String inicial: {}", string);

    let encoded = encode(&string, alfabeto_base64);
    println!("String codificada: {}", encoded);

    let decoded = decode(&encoded, alfabeto_base64);
    println!("String decodificada: {}", decoded);
}

//Quando o texto for fixo, utilizar &str: let string = "ryann";
//Quando precisar construir ou modificar em tempo de execução, utilizar String: let string = String::from("ryann");

//    A          B          C
//01000001   01000010   01000011

//     010000010100001001000011
//010000 | 010100 | 001001 | 000011

//Fórmula para deslocamento: (numero >> deslocamento) & 0x3F

//Base64 sempre vai operar em blocos fixos de 3 bytes, então o deslocamento sempre vai ser 16, 8 e 0 para juntar e 18, 12, 6 e 0 para extrair.
//Verificação de paddings antes de dar push nos grupos3 e grupo4 para não printar caractere a mais.