# Criptografia e Segurança

Implementações de algoritmos criptográficos desenvolvidas do zero em Rust, para a disciplina de **Criptografia e Segurança de Computadores** — Ciência da Computação, Universidade Positivo.

O objetivo do repositório é construir cada primitiva criptográfica a partir dos fundamentos matemáticos, sem depender de bibliotecas de alto nível, para compreender o funcionamento interno de cada algoritmo.

---

## Estrutura do repositório

```
cripto-sec/
├── aes256/            # Cofre de arquivos com AES-256-CBC + PBKDF2
├── base64/            # Codificador/decodificador Base64
├── def_profundidade/  # Etapas da defesa em profundidade
└── learning-rust/     # Estudos e experimentos em Rust
```

---

## aes256 — Cofre de arquivos

Implementação completa de um sistema de cifração de arquivos, construída do zero em Rust.

**Algoritmos implementados manualmente (sem bibliotecas):**

- **AES-256-CBC** — cifração e decifração com suporte a chaves de 128, 192 e 256 bits
  - Key Expansion (Rijndael Key Schedule)
  - SubBytes / InvSubBytes (S-Box e Inv S-Box)
  - ShiftRows / InvShiftRows
  - MixColumns / InvMixColumns (aritmética em GF(2⁸))
  - AddRoundKey
  - Padding PKCS#7
- **PBKDF2** — derivação de chave a partir de senha
- **SHA-256** (_em implementação_) — base do HMAC-SHA256

**Formato do arquivo cifrado:**

```
[ salt (16 bytes) ] [ IV (16 bytes) ] [ ciphertext ]
```

### Como usar

```bash
cd aes256

# Testar contra vetor oficial do NIST
cargo run -- testar

# Cifrar um arquivo
cargo run -- cifrar mensagem.txt

# Decifrar um arquivo
cargo run -- decifrar mensagem.txt.cifrado
```

---

## base64 — Codificador/Decodificador

Implementação do algoritmo Base64 (RFC 4648) do zero em Rust.

```bash
cd base64
# ver instruções de uso no diretório
```

---

## learning-rust

Estudos e experimentos realizados durante o aprendizado da linguagem Rust — exercícios, testes de conceitos e rascunhos relacionados à disciplina.

---

## def_profundidade

Análise completa sobre o caso fictício da empresa "Bar do Índio Solutions", na sequência: [Phishing → Malware → Exploit de SO → Exfiltração]. Os slides mapeia 5 camadas de defesa — Conscientização, Segurança de Rede, Endpoint, Aplicação e Dados, detalhando o que cada camada teria impedido na cadeia de ataque e as medidas concretas de mitigação.

---

## Contexto acadêmico

> Disciplina: Criptografia e Segurança de Computadores — 5º semestre
> Universidade Positivo
> Todos os algoritmos foram implementados a partir das especificações matemáticas originais (NIST FIPS 197, RFC 2104, RFC 8018, RFC 4648), conectando cada linha de código à fórmula correspondente.
