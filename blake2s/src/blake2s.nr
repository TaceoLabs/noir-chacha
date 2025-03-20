global IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

global SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn blake2s_rotr(x: u32, n: u8) -> u32 {
    (x >> n) + (x << (32 - n))
}

fn blake2s_mix(mut a: u32, mut b: u32, mut c: u32, mut d: u32, x: u32, y: u32) -> [u32; 4] {
    a = std::wrapping_add(a, b);
    a = std::wrapping_add(a, x);
    d ^= a;
    d = blake2s_rotr(d, 16);
    c = std::wrapping_add(c, d);
    b ^= c;
    b = blake2s_rotr(b, 12);
    a = std::wrapping_add(a, b);
    a = std::wrapping_add(a, y);
    d ^= a;
    d = blake2s_rotr(d, 8);
    c = std::wrapping_add(c, d);
    b ^= c;
    b = blake2s_rotr(b, 7);
    [a, b, c, d]
}

fn blake2s_compress(input: [u32; 16], mut h: [u32; 8], t: [u32; 2], f: [u32; 2]) -> [u32; 8] {
    let mut state = [
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        IV[4] ^ t[0],
        IV[5] ^ t[1],
        IV[6] ^ f[0],
        IV[7] ^ f[1],
    ];

    for r in 0..10 {
        let sr = SIGMA[r];

        let res = blake2s_mix(
            state[0],
            state[4],
            state[8],
            state[12],
            input[sr[0]],
            input[sr[1]],
        ); // Column 0
        state[0] = res[0];
        state[4] = res[1];
        state[8] = res[2];
        state[12] = res[3];
        let res = blake2s_mix(
            state[1],
            state[5],
            state[9],
            state[13],
            input[sr[2]],
            input[sr[3]],
        ); // Column 1
        state[1] = res[0];
        state[5] = res[1];
        state[9] = res[2];
        state[13] = res[3];
        let res = blake2s_mix(
            state[2],
            state[6],
            state[10],
            state[14],
            input[sr[4]],
            input[sr[5]],
        ); // Column 2
        state[2] = res[0];
        state[6] = res[1];
        state[10] = res[2];
        state[14] = res[3];
        let res = blake2s_mix(
            state[3],
            state[7],
            state[11],
            state[15],
            input[sr[6]],
            input[sr[7]],
        ); // Column 3
        state[3] = res[0];
        state[7] = res[1];
        state[11] = res[2];
        state[15] = res[3];
        let res = blake2s_mix(
            state[0],
            state[5],
            state[10],
            state[15],
            input[sr[8]],
            input[sr[9]],
        ); // Diagonal 1 (main diagonal)
        state[0] = res[0];
        state[5] = res[1];
        state[10] = res[2];
        state[15] = res[3];
        let res = blake2s_mix(
            state[1],
            state[6],
            state[11],
            state[12],
            input[sr[10]],
            input[sr[11]],
        ); // Diagonal 2
        state[1] = res[0];
        state[6] = res[1];
        state[11] = res[2];
        state[12] = res[3];
        let res = blake2s_mix(
            state[2],
            state[7],
            state[8],
            state[13],
            input[sr[12]],
            input[sr[13]],
        ); // Diagonal 3
        state[2] = res[0];
        state[7] = res[1];
        state[8] = res[2];
        state[13] = res[3];
        let res = blake2s_mix(
            state[3],
            state[4],
            state[9],
            state[14],
            input[sr[14]],
            input[sr[15]],
        ); // Diagonal 4
        state[3] = res[0];
        state[4] = res[1];
        state[9] = res[2];
        state[14] = res[3];
    }

    for i in 0..8 {
        h[i] ^= state[i] ^ state[i + 8];
    }
    h
}

pub fn blake2s<let N: u32>(input: [u8; N]) -> [u8; 32] {
    let blocks = (N + 63) / 64;
    let mut counter: u64 = 0;
    let mut h = IV;
    h[0] ^= 0x01010020; // no key provided; = 0x0101kknn where kk is key length and nn is output length

    if N > 0 {
        for block in 0..blocks - 1 {
            counter += 64;
            let t = [counter as u32, (counter >> 32) as u32];
            let mut tmp = [0; 16];
            for i in 0..64 {
                let shift = (i % 4) as u8 * 8;
                tmp[i / 4] += input[64 * block + i] as u32 << shift;
            }
            h = blake2s_compress(tmp, h, t, [0, 0]);
        }
    }

    let mut bytes = N % 64;
    if N > 0 {
        if bytes == 0 {
            bytes = 64;
        }
    }

    counter += bytes as u64;
    let t = [counter as u32, (counter >> 32) as u32];
    let mut tmp = [0; 16];
    for i in 0..bytes {
        let shift = (i % 4) as u8 * 8;
        tmp[i / 4] += input[64 * (blocks - 1) + i] as u32 << shift;
    }
    h = blake2s_compress(tmp, h, t, [0xFFFFFFFF, 0]);

    let mut result = [0; 32];
    for i in 0..8 {
        let tmp: [u8; 4] = u32::to_le_bytes(h[i] as Field);
        for j in 0..4 {
            result[4 * i + j] = tmp[j];
        }
    }
    result
}

#[test]
fn empty_hash() {
    let hash = blake2s([]);
    let expected = [
        0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94, 0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a,
        0x7c, 0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e, 0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0,
        0xee, 0xf9,
    ];
    assert(hash == expected);
}

#[test]
fn zero_hash() {
    let hash = blake2s([0]);
    let expected = [
        0xe3, 0x4d, 0x74, 0xdb, 0xaf, 0x4f, 0xf4, 0xc6, 0xab, 0xd8, 0x71, 0xcc, 0x22, 0x04, 0x51,
        0xd2, 0xea, 0x26, 0x48, 0x84, 0x6c, 0x77, 0x57, 0xfb, 0xaa, 0xc8, 0x2f, 0xe5, 0x1a, 0xd6,
        0x4b, 0xea,
    ];
    assert(hash == expected);
}

#[test]
fn one_block_hash() {
    let hash = blake2s([0xff; 64]);
    let expected = [
        0xee, 0x92, 0xd9, 0xd7, 0x65, 0xaa, 0xc6, 0x54, 0xbc, 0x06, 0x2e, 0xa8, 0xe2, 0x44, 0x56,
        0xbb, 0x1a, 0x73, 0xc8, 0x66, 0x43, 0xbd, 0xac, 0x7e, 0xc4, 0xff, 0x2e, 0xfd, 0x81, 0x72,
        0x10, 0x63,
    ];
    assert(hash == expected);
}

#[test]
fn two_blocks_hash() {
    let hash = blake2s([0xff; 128]);
    let expected = [
        0x20, 0xdf, 0xe3, 0xad, 0x1e, 0xcf, 0xd9, 0xd3, 0xe9, 0xe9, 0xf0, 0x76, 0x23, 0x49, 0x55,
        0x6b, 0x1f, 0x4e, 0x79, 0x70, 0x17, 0x19, 0xcf, 0xb4, 0x93, 0x3e, 0x42, 0xfd, 0xc6, 0x54,
        0x2d, 0xf0,
    ];
    assert(hash == expected);
}

#[test]
fn one_block_plus_one_hash() {
    let hash = blake2s([0xff; 65]);
    let expected = [
        0x2c, 0xdc, 0x28, 0x8f, 0x2a, 0x3d, 0x1a, 0x13, 0x4c, 0xfc, 0xf7, 0x96, 0xf2, 0x35, 0xc1,
        0x39, 0x31, 0xf9, 0xb0, 0x1b, 0x43, 0x07, 0x4e, 0x05, 0x2f, 0x98, 0xd5, 0x01, 0x2a, 0x60,
        0x3a, 0xd6,
    ];
    assert(hash == expected);
}
