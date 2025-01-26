use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

// Constants containng the ciphertexts, in hexadecimal
const CIPHERTEXT_1_HEX: &str = "a869e713c834b210e2e947bb22acc14ebee6a4e16db75913cd859d18eefcbc11084684e0eab925e1956d5be103c2770308ab633147eef522d3afa5a48d0626281b256047a7a7c97e86ff06d65810fce23c2d6134e74d6500a779500df41e819cef878e32122dd6c8b17d6d5ddf7eda890c8e8a682732c1218d97029bf5972f3a1ae02cf0879bd2405444c93bf6455f01f6be3d121bfd0224b2dba49125aa9e8b2728ea86b09a2a32fc54902edd1848000135161f44d57723abaf2646a663b7b55d9b99148896e2066a143320eff65736c6cef1b0fe614fe56186ec94f5c26f79c5ae8bc795a3c08cbb2f2ab0c2d406e1077f37cf695509cbe41294085d0806db";
const CIPHERTEXT_2_HEX: &str = "dd58ed408975a21da3e908ad22a8c110f0a2e8a02484112f8c85d05ca99da61d4d1192b7f8bf66b4986751e6038a70464aaf672049eef63392bcf6e8f64e206e56336105e3f3ca75c9ef1a97460ce6e86c3c6629ad191101ba2a120fe010808aa79f9b62042b9b9a8c3864169e528f1fac538a6f3a27912190970285e9df7c7214f578f385cec84f15588c3ee4591d4782b92d4659e00572a393b5d92bb6988b746da4d2ac976f7dfd5dd479c116040c01351210549c6a2be5bb200de75ce5f408a9cb148ad9a35f2b18242be5ae0233cbd2fdf9ec3202c3379af196b18a7e64c5a78bdc8aa3d685bd2924f1e59053f40d6963d3261c13d0f9199e4c090f018f";
const CIPHERTEXT_3_HEX: &str = "c310e1018a7aa90ca3f505a472ffd90be8aef7e276b6182bc586d618a9d3b107514195a9f6bf6afb8b2956af0581600b5ea668374ba0f37680abaabdd34f3b371b3f6001b0f2d0759aa44897465fe7f33c3a6a34fe58310ca079571cfa189098a3d08c67083dd2d6ac766c00df5dc1990cabcf7c332e913d8a934c96e0c238695ba610fa9eded04d471cc905b75f104f82a62a5d0fe60737f79abed929bc8994662fe5d2ad9d2132fc5ed466c60e040a1c705a054998616cb5a93119a659aae916fd8a1588d9b94e7250312de4fb0536c69dbefff16106c82481fa95b1917e7590bf8f8b8eebd18afe3777f5efd410fd106972d87219048dad34905f092f09ca";

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    // Convert a hexadecimal string into a Vector of bytes
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn xor_bytes(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    // Perform a bitwise XOR on corresponding bytes from two-byte slices
    bytes1.iter()
        .zip(bytes2.iter())
        .map(|(&b1, &b2)| b1 ^ b2)
        .collect()
}

fn crib_drag(xor_bytes: &[u8], crib: &str) -> Vec<(usize, String)> {
    // Perform crib-dragging to find potential segments of plaintext
    let crib_bytes: &[u8] = crib.as_bytes();
    let mut results: Vec<(usize, String)> = Vec::new();

    for i in 0..=xor_bytes.len() - crib_bytes.len() {
        let segment: Vec<u8> = xor_bytes[i..i + crib_bytes.len()].to_vec();
        let possible_plaintext: Vec<u8> = segment
            .iter()
            .zip(crib_bytes.iter())
            .map(|(&x, &c)| x ^ c)
            .collect();

        // Print if all characters are valid ASCII text
        if possible_plaintext.iter().all(|&b| (32..=126).contains(&b)) {
            results.push((i, String::from_utf8(possible_plaintext).unwrap()));
        }
    }

    results
}

fn write_results_to_file(
    crib: &str,
    xor_results: &[Vec<(usize, String)>],
    directory: &str,
) -> std::io::Result<()> {
    // Write results to a file
    let file_name: String = format!("{}.txt", crib.trim().replace(' ', "_"));
    let file_path: std::path::PathBuf = Path::new(directory).join(file_name);

    let mut file: File = File::create(file_path)?;

    writeln!(file, "==================== Results for C1_XOR_C2: ====================")?;
    for result in &xor_results[0] {
        writeln!(file, "Position {}: {}", result.0, result.1)?;
    }

    writeln!(file, "\n==================== Results for C1_XOR_C3: ====================")?;
    for result in &xor_results[1] {
        writeln!(file, "Position {}: {}", result.0, result.1)?;
    }

    writeln!(file, "\n==================== Results for C2_XOR_C3: ====================")?;
    for result in &xor_results[2] {
        writeln!(file, "Position {}: {}", result.0, result.1)?;
    }

    Ok(())
}

fn main() {
    // Main function

    // Convert hexadecimal ciphertexts to Vectors of bytes
    let ciphertext_1: Vec<u8> = hex_to_bytes(CIPHERTEXT_1_HEX);
    let ciphertext_2: Vec<u8> = hex_to_bytes(CIPHERTEXT_2_HEX);
    let ciphertext_3: Vec<u8> = hex_to_bytes(CIPHERTEXT_3_HEX);

    // XOR the ciphertexts
    let c1_xor_c2: Vec<u8> = xor_bytes(&ciphertext_1, &ciphertext_2);
    let c1_xor_c3: Vec<u8> = xor_bytes(&ciphertext_1, &ciphertext_3);
    let c2_xor_c3: Vec<u8> = xor_bytes(&ciphertext_2, &ciphertext_3);

    // List of cribs to check (write to the Vector as we find new parts of the plaintext)
    let cribs: Vec<&str> = vec![" the ", " and ", "tion", "ing ", " to ", " of ", " is ", " Frodo", " Who made the world?", " decrypt", "Who made the world?", "the one who is eating sugar out of my hand,", " the old tales and songs, Mr. Frodo, advent", " circumstance", " circumference", " can't be", " won't be", " and the", " didn't be", "Now she lifts her pale forearms and thoroughly washes her face.", " made the ", " cannot help ", "Yes, that's s", "ho made the w", "making encrypt", " security measures", "said Sam, \"And we shouldn't be here at al", " breaking encryption "];
    let results_dir: &str = "results";

    fs::create_dir_all(results_dir).unwrap();

    for crib in cribs {
        println!("Performing crib-dragging attack on word: {}", crib);

        let xor_results: Vec<Vec<(usize, String)>> = vec![
            crib_drag(&c1_xor_c2, crib),
            crib_drag(&c1_xor_c3, crib),
            crib_drag(&c2_xor_c3, crib),
        ];

        write_results_to_file(crib, &xor_results, results_dir).unwrap();
    }
}
