global IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

global SIGMA: [[u8; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

fn blake3_rotr(x: u32, n: u8) -> u32 {
    (x >> n) + (x << (32 - n))
}

fn blake3_mix(mut a: u32, mut b: u32, mut c: u32, mut d: u32, x: u32, y: u32) -> [u32; 4] {
    a = std::wrapping_add(a, b);
    a = std::wrapping_add(a, x);
    d ^= a;
    d = blake3_rotr(d, 16);
    c = std::wrapping_add(c, d);
    b ^= c;
    b = blake3_rotr(b, 12);
    a = std::wrapping_add(a, b);
    a = std::wrapping_add(a, y);
    d ^= a;
    d = blake3_rotr(d, 8);
    c = std::wrapping_add(c, d);
    b ^= c;
    b = blake3_rotr(b, 7);
    [a, b, c, d]
}

fn blake3_compress(
    input: [u32; 16],
    mut h: [u32; 8],
    t: [u32; 2],
    blocklen: u32,
    flags: u32,
) -> [u32; 8] {
    let mut state = [
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], IV[0], IV[1], IV[2], IV[3], t[0], t[1],
        blocklen, flags,
    ];

    for r in 0..7 {
        let sr = SIGMA[r];

        let res = blake3_mix(
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
        let res = blake3_mix(
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
        let res = blake3_mix(
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
        let res = blake3_mix(
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
        let res = blake3_mix(
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
        let res = blake3_mix(
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
        let res = blake3_mix(
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
        let res = blake3_mix(
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
        h[i] = state[i] ^ state[i + 8];
    }
    h
}

pub fn blake3_chunk_chaining<let N: u32>(input: [u8; N], chunk_index: u64, flag: u32) -> [u32; 8] {
    assert(N <= 1024);
    let blocks = (N + 63) / 64;
    let mut h = IV;

    let chunk_start: u32 = 1;
    let chunk_end: u32 = 2;
    let root_flag: u32 = 8;
    assert((flag == 0) | (flag == root_flag));

    let t = [chunk_index as u32, (chunk_index >> 32) as u32];

    let mut used_flag = chunk_start;
    if N > 0 {
        for block in 0..blocks - 1 {
            let mut tmp = [0; 16];
            for i in 0..64 {
                let shift = (i % 4) as u8 * 8;
                tmp[i / 4] += input[64 * block + i] as u32 << shift;
            }
            h = blake3_compress(tmp, h, t, 64, used_flag);
            used_flag = 0;
        }
    }

    let mut bytes = N % 64;
    if N > 0 {
        if bytes == 0 {
            bytes = 64;
        }
    }

    used_flag += chunk_end + flag;

    let mut tmp = [0; 16];
    for i in 0..bytes {
        let shift = (i % 4) as u8 * 8;
        tmp[i / 4] += input[64 * (blocks - 1) + i] as u32 << shift;
    }
    blake3_compress(tmp, h, t, bytes, used_flag)
}

pub unconstrained fn blake3<let N: u32>(input: [u8; N]) -> [u8; 32] {
    let root_flag: u32 = 8;
    let parent_flag: u32 = 4;
    let mut result = [0; 32];

    if N <= 1024 {
        let h = blake3_chunk_chaining(input, 0, root_flag);

        for i in 0..8 {
            let tmp: [u8; 4] = u32::to_le_bytes(h[i] as Field);
            for j in 0..4 {
                result[4 * i + j] = tmp[j];
            }
        }
    } else {
        // At least two chunks
        let num_chunks = (N + 1023) / 1024;
        let mut nodes = [[0; 8]; (N + 1023) / 1024];
        for i in 0..num_chunks - 1 {
            let start = i * 1024;
            let mut input_ = [0; 1024];
            for i in 0..1024 {
                input_[i] = input[start + i];
            }
            nodes[i] = blake3_chunk_chaining(input_, i as u64, 0);
        }

        let start = (num_chunks - 1) * 1024;
        if N % 1024 == 0 {
            let mut input_ = [0; 1024];
            for i in 0..1024 {
                input_[i] = input[start + i];
            }
            nodes[num_chunks - 1] = blake3_chunk_chaining(input_, num_chunks as u64 - 1, 0);
        } else {
            let mut input_ = [0; N % 1024];
            for i in 0..N % 1024 {
                input_[i] = input[start + i];
            }
            nodes[num_chunks - 1] = blake3_chunk_chaining(input_, num_chunks as u64 - 1, 0);
        }

        // Merkle tree
        let mut len = num_chunks;
        let mut new_len = len / 2;
        while len != 1 {
            for i in 0..new_len {
                let flag = if len == 2 {
                    root_flag + parent_flag
                } else {
                    parent_flag
                };
                let mut input = [0; 16];
                for n in 0..8 {
                    input[n] = nodes[2 * i][n];
                    input[n + 8] = nodes[2 * i + 1][n];
                }
                nodes[i] = blake3_compress(input, IV, [0, 0], 64, flag);
                if len % 2 == 1 {
                    nodes[new_len] = nodes[len - 1];
                    new_len += 1;
                }
                len = new_len;
                new_len = len / 2;
            }
        }

        for i in 0..8 {
            let tmp: [u8; 4] = u32::to_le_bytes(nodes[0][i] as Field);
            for j in 0..4 {
                result[4 * i + j] = tmp[j];
            }
        }
    }

    result
}

#[test]
fn empty_hash() {
    // Safety: This is just a reference impl
    let hash = unsafe { blake3([]) };
    let expected = [
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9,
        0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f,
        0x32, 0x62,
    ];
    assert(hash == expected);
}

#[test]
fn zero_hash() {
    // Safety: This is just a reference impl
    let hash = unsafe { blake3([0]) };
    let expected = [
        0x2d, 0x3a, 0xde, 0xdf, 0xf1, 0x1b, 0x61, 0xf1, 0x4c, 0x88, 0x6e, 0x35, 0xaf, 0xa0, 0x36,
        0x73, 0x6d, 0xcd, 0x87, 0xa7, 0x4d, 0x27, 0xb5, 0xc1, 0x51, 0x02, 0x25, 0xd0, 0xf5, 0x92,
        0xe2, 0x13,
    ];
    assert(hash == expected);
}

#[test]
fn one_block_hash() {
    // Safety: This is just a reference impl
    let hash = unsafe { blake3([0xff; 64]) };
    let expected = [
        0xa9, 0x0f, 0x27, 0xf0, 0xa6, 0xca, 0xd0, 0x8c, 0xe5, 0xb5, 0xff, 0xd6, 0xcb, 0xa9, 0xdd,
        0x44, 0xe2, 0x92, 0x59, 0x7d, 0xb9, 0xde, 0xdf, 0xd0, 0x6e, 0xd6, 0x09, 0xf2, 0x27, 0x6d,
        0x69, 0xd9,
    ];
    assert(hash == expected);
}

#[test]
fn two_blocks_hash() {
    // Safety: This is just a reference impl
    let hash = unsafe { blake3([0xff; 128]) };
    let expected = [
        0x59, 0x5f, 0xef, 0xe6, 0x18, 0xcc, 0x45, 0x65, 0x0e, 0x66, 0x11, 0xa0, 0xc8, 0x62, 0xd1,
        0xc5, 0x28, 0x24, 0xe3, 0x1d, 0x3d, 0x5a, 0x65, 0x5e, 0x14, 0x09, 0xa7, 0xf9, 0xb0, 0xa5,
        0xcd, 0x74,
    ];
    assert(hash == expected);
}

#[test]
fn one_block_plus_one_hash() {
    // Safety: This is just a reference impl
    let hash = unsafe { blake3([0xff; 65]) };
    let expected = [
        0xb7, 0xeb, 0x32, 0xd9, 0x9c, 0x18, 0xbe, 0xdb, 0x02, 0xd8, 0xb0, 0xff, 0xe0, 0x35, 0x1c,
        0x5f, 0x39, 0x94, 0xb3, 0xf5, 0xa2, 0x5a, 0x25, 0x79, 0x00, 0x8e, 0xdb, 0x3e, 0xea, 0xcc,
        0xe1, 0xa1,
    ];
    assert(hash == expected);
}

#[test]
fn blake3_2048_hash() {
    // Safety: This is just a reference impl
    let hash = unsafe { blake3([0xff; 2048]) };
    let expected = [
        0xbd, 0x6c, 0xb2, 0x26, 0x66, 0x0e, 0x34, 0xf6, 0x00, 0x0c, 0xfc, 0xdc, 0xa6, 0x6b, 0x57,
        0x50, 0xa6, 0x29, 0x77, 0x7f, 0x4c, 0x98, 0x7c, 0xee, 0x2c, 0x64, 0x80, 0x7f, 0x05, 0x6f,
        0xdf, 0x8c,
    ];
    assert(hash == expected);
}

#[test]
fn blake3_2049_hash() {
    // Safety: This is just a reference impl
    let hash = unsafe { blake3([0xff; 2049]) };
    let expected = [
        0xab, 0x37, 0xeb, 0x79, 0x81, 0xe4, 0xb7, 0xed, 0x5d, 0x53, 0x2b, 0x98, 0xfa, 0x31, 0x9e,
        0x24, 0x63, 0xb9, 0x3c, 0xd2, 0xf2, 0x9b, 0x4f, 0xda, 0x2e, 0x88, 0x6d, 0x15, 0x7c, 0x2f,
        0x0e, 0x6f,
    ];
    assert(hash == expected);
}
