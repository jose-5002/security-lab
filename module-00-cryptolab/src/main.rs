use std::env;
use std::process;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::{rngs::OsRng, RngCore};

fn hex_encode(data: &[u8]) -> String{
    let mut result = String::with_capacity(data.len() * 2);
    let hex_chars = b"0123456789abcdef";

    for &byte in data{
        let high = (byte >> 4) as usize;
        let low = (byte & 0x0F) as usize;
        result.push(hex_chars[high] as char);
        result.push(hex_chars[low] as char);
    }
    result

}

fn hex_decode(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 {
        return Err("Hex string must have an even length".into());
    }

    let mut bytes = Vec::with_capacity(hex_str.len() / 2);
    let chars = hex_str.as_bytes();

    let decode_nibble = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("Invalid hex character: {}", c as char)),
        }
    };

    for chunk in chars.chunks(2) {
        let high = decode_nibble(chunk[0])?;
        let low = decode_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }

    Ok(bytes)
}



fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

fn b64_decode(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(encoded)
}

fn print_decoded_result(data: &[u8]) {
    match std::str::from_utf8(data) {
        Ok(text) => {
            println!("Decoded Text: {}", text);
        }
        Err(_) => {
            println!(
                "Decoded Data (Binary/Non-UTF8): {} bytes | Preview: {}",
                data.len(),
                String::from_utf8_lossy(data)
            );
        }
    }
}


fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, String> {
    if a.len() != b.len(){
        return Err("Invalid key length".to_string())
    }
    Ok(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
}

pub fn caesar_shift(text: &str, shift: i32) -> String {
    // Wrap negative and large shifts into the valid 0..25 range
    let shift = (((shift % 26) + 26) % 26) as u8;

    text.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + shift) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + shift) % 26) + b'A') as char,
            _ => c, // Pass through punctuation and spaces unchanged
        })
        .collect()
}

const ENGLISH_FREQUENCIES: [f64; 26] = [
    8.17, 1.29, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, // A - I
    0.15, 0.77, 4.03, 2.41, 6.75, 7.51, 1.93, 0.10, 5.99,  // J - R (J = 0.15)
    6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07,        // S - Z (X = 0.15)
];

pub fn score_text(text: &str) -> f64 {
    let mut counts = [0usize; 26];
    let mut total_letters = 0usize;

    // Step 2: Count how often each letter A-Z appears
    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            let idx = (c.to_ascii_uppercase() as usize) - ('A' as usize);
            counts[idx] += 1;
            total_letters += 1;
        }
    }

    if total_letters == 0 {
        return 0.0;
    }

    // Step 3: Multiply observed fraction by English frequency and sum into one score
    let mut score = 0.0;
    for i in 0..26 {
        let observed_fraction = counts[i] as f64 / total_letters as f64;
        score += observed_fraction * ENGLISH_FREQUENCIES[i];
    }

    score
}

fn run_codec(args: &[String]) -> Result<(), String> {

    if args.is_empty() || args.len() < 2 {
        return Err("usage: codec <hex-encode|hex-decode|b64-encode|b64-decode> <value>".into());
    }

    match args.first().map(String::as_str) {
        Some("hex-encode") => {
            println!("{}", hex_encode(&( args[1].as_str().as_bytes() ) ));
            Ok(())
        }
        Some("hex-decode") => {
            let decode = hex_decode(&(args[1].as_str() ))?;
            print_decoded_result(&decode);
            Ok(()) 
        }

        Some("b64-encode") => { 
            println!("{}", b64_encode(&( args[1].as_str().as_bytes())) );
            Ok(()) 
        }
        Some("b64-decode") => { 
            let decode = b64_decode(&(args[1].as_str() )).map_err(|e| e.to_string())?;
            print_decoded_result(&decode);
            Ok(()) 
        }
        _ => Err("usage: codec <hex-encode|hex-decode|b64-encode|b64-decode> <value>".into()),
    }
}

fn run_otp(args: &[String]) -> Result<(), String> {
    if args.is_empty() || args.len() < 4 {
         if args[0].as_str() == "misuse-demo"{
            let result = misuse_demo()?;
            if result{
                println!("Misuse demo successful: XOR of two ciphertexts matches XOR of two plaintexts.");
            } else {
                println!("Misuse demo failed: XOR of two ciphertexts does not match XOR of two plaintexts.");
            }
            return Ok(());
        }
        return Err("usage: cryptolab otp <encrypt|decrypt> <in> <key_file> <out>".into());
    }
   

    let input_file = args[1].as_str();
    let data: Vec<u8> = std::fs::read(input_file).map_err(|e| format!("couldn't read {input_file}: {e}"))?;

    let key_file = args[2].as_str();
    let output_file = args[3].as_str();

    match args.first().map(String::as_str) {
        Some("encrypt") => {
            let mut key = vec![0u8; data.len()];
            OsRng.fill_bytes(&mut key);
            std::fs::write(key_file, &key).map_err(|e| format!("couldn't write {key_file}: {e}"))?;

            let ciphertext = xor(&data, &key)?;
            std::fs::write(output_file, &ciphertext).map_err(|e| format!("couldn't write {output_file}: {e}"))?;
            Ok(())
        }

        Some("decrypt") => {
            let key:Vec<u8> = std::fs::read(key_file).map_err(|e| format!("couldn't read {key_file}: {e}"))?;
            let org_msg = xor(&data, &key)?;
            std::fs::write(output_file, &org_msg).map_err(|e| format!("couldn't write {output_file}: {e}"))?;
            Ok(())
        }
        _ => Err("usage: cryptolab otp <encrypt|decrypt> <in> <key_file> <out>".into()),

    }
}

pub fn run_caesar(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("Usage: cryptolab caesar <encrypt|decrypt|crack> [shift] [text]".into());
    }

    let action = args[0].as_str();

    match action {
        "encrypt" | "decrypt" => {
            if args.len() < 3 {
                return Err(format!("Usage: cryptolab caesar {action} <shift> <text>"));
            }

            let mut shift: i32 = args[1]
                .parse()
                .map_err(|_| format!("Invalid shift '{}': must be an integer", args[1]))?;

            if action == "decrypt" {
                shift = -shift;
            }

            let text = args[2..].join(" ");
            let output = caesar_shift(&text, shift);
            println!("{output}");
        }
        "crack" => {
            if args.len() < 2 {
                return Err("Usage: cryptolab caesar crack <text>".into());
            }

            let text = args[1..].join(" ");
            println!("Brute-forcing all 25 shift possibilities with scores:\n");

            let mut highest_score = -1.0;
            let mut winner_shift = 1;
            let mut winner_text = String::new();

            // Try all 25 shifts and score each one
            for key in 1..26 {
                let decrypted = caesar_shift(&text, -key);
                let score = score_text(&decrypted);

                println!("Shift {:2} | Score: {:6.3} | {}", key, score, decrypted);

                // Step 4: Track the highest score
                if score > highest_score {
                    highest_score = score;
                    winner_shift = key;
                    winner_text = decrypted;
                }
            }

            println!("\n----------------------------------------");
            println!("WINNER: Shift {} (Score: {:.3})", winner_shift, highest_score);
            println!("Decrypted: {}", winner_text);
        }
        other => {
            return Err(format!(
                "Unknown caesar action: '{other}'. Expected 'encrypt', 'decrypt', or 'crack'."
            ))
        }
    }

    Ok(())
}

pub fn misuse_demo() -> Result<bool, String>{
    let text1 = b"THE EAGLE FLIES AT MIDNIGHT";
    let text2 = b"THE ENEMY RETREATS AT DAWN!";
    let mut key = vec![0u8; text2.len()];
    OsRng.fill_bytes(&mut key);

    let ciphertext1 = xor(text1, &key)?;
    let ciphertext2 = xor(text2, &key)?;

    let combined = xor(&ciphertext1, &ciphertext2)?;
    let initial_combo = xor(text1, text2)?;

    println!("XOR of two ciphertext: {:?}", combined);
    println!("original XOR of plaintext: {:?}", initial_combo);

    Ok(combined==initial_combo)
}


fn main() {
    let args: Vec<String> = env::args().collect();
    // args[0] is the binary's own name. args[1] is the group ("codec"/"otp"/"caesar").
    // args[2] is the action ("hex-encode"/"encrypt"/...). args[3..] are its own arguments.
    if args.len() < 2 {
        eprintln!("Usage: cryptolab <codec|otp|caesar> <action> [args...]");
        process::exit(1);
    }

    let result = match args[1].as_str() {
        "codec" => run_codec(&args[2..]),
        "otp" => run_otp(&args[2..]),
        "caesar" => run_caesar(&args[2..]),
        other => Err(format!("unknown command group: {other}")),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }

}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex_decode(&hex_encode(b"hello")).unwrap(), b"hello");
    }

    #[test]
    fn caesar_trip() {
        assert_eq!(caesar_shift("attack at dawn", 3), "dwwdfn dw gdzq" )
    }

    #[test]
    fn otp_trip() {
        let msg_file = "msg.txt";
        let msg = "Welcome to cryptography";
        std::fs::write(msg_file, msg).unwrap();

        let key_file = "key.hex";
        let cipher_file = "ct.bin";

        let args: Vec<String> = vec!["encrypt".to_string(), msg_file.to_string(), key_file.to_string(), cipher_file.to_string() ];
        run_otp(&args).unwrap();

        let msg2_file = "msg2.txt";
        let args2: Vec<String> = vec!["decrypt".to_string(), cipher_file.to_string(), key_file.to_string(), msg2_file.to_string() ];
        run_otp(&args2).unwrap();

        let data1 = std::fs::read(msg_file).unwrap();
        let data2 = std::fs::read(msg2_file).unwrap();

        assert_eq!(data1, data2)

    }

    #[test]
    fn xor_trip(){
        let text = b"Hello, World!";
        let mut key = vec![0u8; text.len()];
        OsRng.fill_bytes(&mut key);
        let ciphertext = xor(text, &key).unwrap();
        let decrypted = xor(&ciphertext, &key).unwrap();
        assert_eq!(text, &decrypted[..]);
    }
}
