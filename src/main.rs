/* 
 * RC4 Encryption/Decryption Algorithm 
 * Can be used for both encryption and decryption because it is symmetric
 */
use std::{env, fs, io};
use std::time::Instant;

// Generates the 256-byte permutation array based on the key
fn ksa(key: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j = 0;
    for i in 0..256 {
        j = (j + (s[i] as usize) + key[i & 15] as usize & 255) & 255;
        s.swap(i, j);
    }
    s
}

// Generates the cipher text given the original text and the key
fn rc4(text: &[u8], key: &[u8]) -> Vec<u8> {
    let len = text.len();
    let mut ciphertext = vec![0u8; len];
    let mut s = ksa(key);

    let mut i = 0;
    let mut j = 0;
    for (idx, char) in text.iter().enumerate() {
        i = (i + 1) & 255;
        j = (j + (s[i] as usize)) & 255;
        s.swap(i, j);
        ciphertext[idx] = s[(s[i] as usize + s[j] as usize) & 255] ^ char;
    }
    ciphertext
}

// Testing the RC4 Algorithm
fn main() -> io::Result<()> {
    const TEXT_IDX: usize = 1;
    const KEY_IDX: usize = 2;
    const BITS_IDX: usize = 3;
    
    let args: Vec<String> = env::args().collect();
    let text_file = fs::read_to_string(&args[TEXT_IDX])?;
    let text = text_file.as_bytes();
    let key = u128::from_str_radix(&fs::read_to_string(&args[KEY_IDX])?, 16).unwrap();
    let set_bits = args[BITS_IDX].parse::<u128>().unwrap();

    let mask = (1 << set_bits) - 1;
    let ciphertext = &rc4(&text, (key | mask).to_be_bytes().as_ref());

    let start_time = Instant::now();
    let start_guess = key & !mask;
    let mut i = 0;
    for guess in start_guess..(start_guess + (1 << set_bits)) {
        i += 1;
        let text_guess = rc4(ciphertext, guess.to_be_bytes().as_ref());
        if text_guess == text {
            break;
        }
    }
    
    println!("Iterations: {i}\nTime: {:?}", start_time.elapsed());
    Ok(())
}
