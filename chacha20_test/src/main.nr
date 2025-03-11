// fn main(key: [u32; 8], nonce: pub [u32; 3], counter: pub u32, input: [u32; 16]) -> pub [u32; 16] {
//     chacha20::chacha20_u32::chacha20(key, nonce, counter, input)
// }

// fn main(
//     key: [[bool; 32]; 8],
//     nonce: pub [[bool; 32]; 3],
//     counter: pub [bool; 32],
//     input: [[bool; 32]; 16],
// ) -> pub [[bool; 32]; 16] {
//     chacha20::chacha20_bitwise::chacha20(key, nonce, counter, input)
// }

fn main(
    key: [[Field; 32]; 8],
    nonce: pub [[Field; 32]; 3],
    counter: pub [Field; 32],
    input: [[Field; 32]; 16],
) -> pub [[Field; 32]; 16] {
    chacha20::chacha20_bitwise_field::chacha20(key, nonce, counter, input)
}
