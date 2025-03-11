fn chacha20_rotl(x: u32, n: u8) -> u32 {
    (x << n) | (x >> (32 - n))
}

fn chacha20_qr(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> [u32; 4] {
    a = std::wrapping_add(a, b);
    d ^= a;
    d = chacha20_rotl(d, 16);
    c = std::wrapping_add(c, d);
    b ^= c;
    b = chacha20_rotl(b, 12);
    a = std::wrapping_add(a, b);
    d ^= a;
    d = chacha20_rotl(d, 8);
    c = std::wrapping_add(c, d);
    b ^= c;
    b = chacha20_rotl(b, 7);
    [a, b, c, d]
}

pub fn chacha20_block(input: [u32; 16]) -> [u32; 16] {
    let mut state = input;

    for _ in 0..10 {
        let res = chacha20_qr(state[0], state[4], state[8], state[12]); // Column 0
        state[0] = res[0];
        state[4] = res[1];
        state[8] = res[2];
        state[12] = res[3];
        let res = chacha20_qr(state[1], state[5], state[9], state[13]); // Column 1
        state[1] = res[0];
        state[5] = res[1];
        state[9] = res[2];
        state[13] = res[3];
        let res = chacha20_qr(state[2], state[6], state[10], state[14]); // Column 2
        state[2] = res[0];
        state[6] = res[1];
        state[10] = res[2];
        state[14] = res[3];
        let res = chacha20_qr(state[3], state[7], state[11], state[15]); // Column 3
        state[3] = res[0];
        state[7] = res[1];
        state[11] = res[2];
        state[15] = res[3];
        let res = chacha20_qr(state[0], state[5], state[10], state[15]); // Diagonal 1 (main diagonal)
        state[0] = res[0];
        state[5] = res[1];
        state[10] = res[2];
        state[15] = res[3];
        let res = chacha20_qr(state[1], state[6], state[11], state[12]); // Diagonal 2
        state[1] = res[0];
        state[6] = res[1];
        state[11] = res[2];
        state[12] = res[3];
        let res = chacha20_qr(state[2], state[7], state[8], state[13]); // Diagonal 3
        state[2] = res[0];
        state[7] = res[1];
        state[8] = res[2];
        state[13] = res[3];
        let res = chacha20_qr(state[3], state[4], state[9], state[14]); // Diagonal 4
        state[3] = res[0];
        state[4] = res[1];
        state[9] = res[2];
        state[14] = res[3];
    }

    for i in 0..16 {
        state[i] = std::wrapping_add(input[i], state[i]);
    }

    state
}

pub fn chacha20(key: [u32; 8], nonce: [u32; 3], counter: u32, input: [u32; 16]) -> [u32; 16] {
    let state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, key[0], key[1], key[2], key[3], key[4],
        key[5], key[6], key[7], nonce[0], nonce[1], nonce[2], counter,
    ];

    let mut output = chacha20_block(state);

    for i in 0..16 {
        output[i] = std::wrapping_add(output[i], input[i]);
    }
    output
}

#[test]
fn test_chacha20_rotl() {
    let inp: u32 = 0x12345678;
    let out = chacha20_rotl(inp, 16);
    assert_eq(out, 0x56781234);
    let inp: u32 = 0x12345678;
    let out = chacha20_rotl(inp, 7);
    assert_eq(out, 0x1a2b3c09);
}

#[test]
fn test_chacha20_qr() {
    let state: [u32; 4] = [0x516461b1, 0x2a5f714c, 0x53372767, 0x3d631689];

    let expected: [u32; 4] = [0xbdb886dc, 0xcfacafd2, 0xe46bea80, 0xccc07c79];

    let res = chacha20_qr(state[0], state[1], state[2], state[3]);
    for i in 0..4 {
        assert_eq(res[i], expected[i]);
    }
}

#[test]
fn test_chacha20_block() {
    let state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
        0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
        0x4a000000, 0x00000000,
    ];

    let expected = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
        0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
        0xe883d0cb, 0x4e3c50a2,
    ];

    let output = chacha20_block(state);

    for i in 0..16 {
        assert_eq(output[i], expected[i]);
    }
}
