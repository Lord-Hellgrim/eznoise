#![allow(non_snake_case)]
use std::arch::x86_64::{__m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aesimc_si128, _mm_aeskeygenassist_si128, _mm_load_si128, _mm_loadu_si128, _mm_setzero_si128, _mm_shuffle_epi32, _mm_slli_si128, _mm_store_si128, _mm_storeu_si128, _mm_xor_si128};


// These are the round constants for the AES key expansion algorithm. Source: "NIST.FIPS.197-upd1.pdf"
const RCON: [u32;10] = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000];

// Representation of the reduction polynomial for the GCM step
const POLY_HIGH: u128 = 1; // x^128
const POLY_LOW: u128 = 0b111000001; // x^7 + x^2 + x + 1


#[cfg(not(target_feature="sse"))]
pub fn array_xor(a: [u8;16], b: [u8;16]) -> [u8;16] {
    let mut c = [0u8;16];
    let mut i = 0;
    while i < 15 {
        c[i] = a[i] ^ b[i];
        i += 1;
    }
    c
}   





fn array16_from_slice(slice: &[u8]) -> [u8;16] {
    if slice.len() != 16 {
        panic!("Slice is not 16 bytes long\nSlice: {:x?}", slice);
    }
    let mut output = [0u8;16];
    let mut i = 0;
    while i < 16 {
        output[i] = slice[i];
        i += 1;
    }
    output
}


fn pkcs_pad16(a: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    if a.len()%16 == 0 {
        output.extend_from_slice(a);
    } else {
        output.extend_from_slice(a);
        let mut i = 0;
        let pad: u8 = 16-((a.len()%16) as u8);
        while i < pad {
            output.push(pad);
            i += 1;
        }
    }
    assert!(output.len()%16 == 0);
    output
}

fn pkcs_unpad(mut a: Vec<u8>) -> Vec<u8> {
    let num: usize = a[a.len()-1] as usize;
    
    for _ in 0..num {
        a.pop();
    }
    a

}

fn ceildiv(a: usize, b: usize) -> usize {
    if a%b==0 {
        a/b
    } else {
        a/b + 1
    }
}

fn LSB(num: usize, bits: u32) -> usize {
    num & ((2 as usize).pow(bits) - 1)
}


fn multiply_and_reduce_128(a_high: u64, a_low: u64, b_high: u64, b_low: u64) -> u128 {
    let ll = a_low.wrapping_mul(b_low);
    let lh = a_low.wrapping_mul(b_high);
    let hl = a_high.wrapping_mul(b_low);
    let hh = a_high.wrapping_mul(b_high);

    let mid = lh.wrapping_add(hl);

    let res_low = ll.wrapping_add(mid.wrapping_shl(64));
    let res_high = hh.wrapping_add(mid.wrapping_shr(64))
        .wrapping_add(if res_low < ll { 1 } else { 0 }) // carry from the low addition

        .wrapping_add(a_high.wrapping_mul(b_high));

    let (mut high, mut low) = (res_high as u128, res_low as u128);
    while high > 0 {
        let leading_zeros = high.leading_zeros();
        // Shift our polynomial so that x^128 aligns with the highest set bit
        let ph = POLY_HIGH.wrapping_shl(128 - leading_zeros);
        let pl = POLY_LOW.wrapping_shl(128 - leading_zeros)
            | POLY_HIGH.wrapping_shr(leading_zeros + 1);

        high ^= ph;
        low ^= pl;
    }

    low

}



// // THIS IS AN UNFINISHED IMPLEMENTATION OF GCM FOR THE AES128 ENCRYPTION. I'LL GET BECK TO THIS LATER (flw...)
// fn GHASH(X: &[u8], hashkey: &[u8;16]) -> Vec<u8> {
//     let Y0 = [0u8;16];
//     let X = pkcs_pad16(X);
//     let mut Y = Vec::new();
//     Y.extend_from_slice(&Y0);
//     let mut i = 16;
//     while i < X.len() {
//         let Yi_i = array16_from_slice(&Y[i-16..i]);
//         let Xi = array16_from_slice(&X[i..i+16]);
//         let temp = unsafe { array_xor(Yi_i, Xi) };
//         let temp_high = u64::from_le_bytes([temp[0], temp[1], temp[2], temp[3], temp[4], temp[5], temp[6], temp[7]]);
//         let temp_low = u64::from_le_bytes([temp[8], temp[9], temp[10], temp[11], temp[12], temp[13], temp[14], temp[15]]);
//         let hashkey_high = u64::from_le_bytes([hashkey[0], hashkey[1], hashkey[2], hashkey[3], hashkey[4], hashkey[5], hashkey[6], hashkey[7]]);
//         let hashkey_low = u64::from_le_bytes([hashkey[8], hashkey[9], hashkey[10], hashkey[11], hashkey[12], hashkey[13], hashkey[14], hashkey[15]]);
//         Y.extend_from_slice(&multiply_and_reduce_128(temp_high, temp_low, hashkey_high, hashkey_low).to_le_bytes());
//         i += 16;
//     }
//     Y
// }

#[derive(Clone)]
pub struct Nonce {
    iv: [u8;12],
    num: u32,
}

impl Nonce {
    fn block(&self) -> [u8;16] {
        let mut output = [0u8;16];
        output[0..12].copy_from_slice(&self.iv);
        output[12..].copy_from_slice(&self.num.to_be_bytes());
        output
    }
}


pub fn AESGCM256(text: &mut [u8], key: [u8;32], iv: [u8;12]) {
    let tag = [0u8;16];
    let round_keys = expand_key_256(&key);

    let tag = encrypt_one_block_256(array_to_simd(&tag), &round_keys);
    let mut y = Nonce {iv, num: 1};

    let mut i = 0;
    while i < text.len()/16 {
        y.num = y.num.wrapping_add(1);
        let E = encrypt_one_block_256(array_to_simd(&y.block()), &round_keys);
        let P = array_to_simd(&array16_from_slice(&text[i..i+16]));
        let ci = unsafe { _mm_xor_si128(E, P) };
        unsafe { _mm_storeu_si128(text[i..i+16].as_mut_ptr().cast(), ci); };


        i += 16;
    }
    y.num = y.num.wrapping_add(1);
    let en = simd_to_array(encrypt_one_block_256(array_to_simd(&y.block()), &round_keys));
    let mut j = 0;
    while i < text.len() {
        text[i] ^= en[j];
        i += 1;
        j += 1;
    }




}


pub fn expand_key_256(key: &[u8;32]) -> [__m128i; 15] {
    let mut w = unsafe { [_mm_setzero_si128();15] };
    w[0] = unsafe { _mm_loadu_si128(key[0..16].as_ptr() as *const __m128i) };
    w[1] = unsafe { _mm_loadu_si128(key[16..32].as_ptr() as *const __m128i) };


    let mut work1 = unsafe { _mm_loadu_si128(key[0..16].as_ptr() as *const __m128i) };
    let mut work2 = unsafe { _mm_loadu_si128(key[16..32].as_ptr() as *const __m128i) };
    
    // EXPAND1
    let mut i = 2; 
    loop {
        let mut temp = unsafe { _mm_slli_si128(work1, 4) };
        work1 = unsafe { _mm_xor_si128(work1, temp) };
        temp =  unsafe { _mm_slli_si128(work1, 8) };
        work1 = unsafe { _mm_xor_si128(work1, temp) };
        match i/2 {
            1 => temp = unsafe { _mm_aeskeygenassist_si128(work2, 0x01) },
            2 => temp = unsafe { _mm_aeskeygenassist_si128(work2, 0x02) },
            3 => temp = unsafe { _mm_aeskeygenassist_si128(work2, 0x04) },
            4 => temp = unsafe { _mm_aeskeygenassist_si128(work2, 0x08) },
            5 => temp = unsafe { _mm_aeskeygenassist_si128(work2, 0x10) },
            6 => temp = unsafe { _mm_aeskeygenassist_si128(work2, 0x20) },
            7 => temp = unsafe { _mm_aeskeygenassist_si128(work2, 0x40) },
            _ => panic!("Invalid RCON index"),
        };
        temp = unsafe { _mm_shuffle_epi32(temp, 0xFF) };
        work1 = unsafe { _mm_xor_si128(work1, temp) };
        
        unsafe { _mm_storeu_si128(&mut w[i], work1) };

        i += 1;

        if i >= 14 {
            break
        }
        //EXPAND2
        temp =  unsafe {_mm_slli_si128(work2, 4) };
        work2 = unsafe {_mm_xor_si128(work2, temp) };
        temp =  unsafe {_mm_slli_si128(work2, 8) };
        work2 = unsafe {_mm_xor_si128(work2, temp) };
        temp =  unsafe {_mm_aeskeygenassist_si128(work1, 0) };
        temp =  unsafe {_mm_shuffle_epi32(temp, 0xAA) };
        work2 = unsafe {_mm_xor_si128(work2, temp) };
        unsafe { _mm_storeu_si128(&mut w[i], work2) };

        i += 1;

    }   

    w

}

#[inline]
fn simd_to_array(input: __m128i) -> [u8;16] {
    let mut output = [0u8;16];
    unsafe { _mm_storeu_si128(output.as_mut_ptr().cast(), input); };
    output
}

#[inline]
fn simd_to_array_aligned(input: __m128i) -> [u8;16] {
    let mut output = [0u8;16];
    unsafe { _mm_store_si128(output.as_mut_ptr().cast(), input); };
    output
}

#[inline]
fn array_to_simd(input: &[u8;16]) -> __m128i {
    unsafe { _mm_loadu_si128(input.as_ptr().cast()) }
}

#[inline]
fn array_to_simd_aligned(input: &[u8;16]) -> __m128i {
    unsafe { _mm_load_si128(input.as_ptr().cast()) }
}

// AES128 encryption
fn encrypt_one_block_256(block: __m128i, round_keys: &[__m128i;15]) -> __m128i {

    let mut ciphertext = unsafe { _mm_xor_si128(block, round_keys[0]) };
    
    let mut i = 1;
    while i < 14 {
        ciphertext = unsafe { _mm_aesenc_si128(ciphertext, round_keys[i]) };
        
        i += 1;
    }
    ciphertext = unsafe { _mm_aesenclast_si128(ciphertext, round_keys[14]) };

    ciphertext

}

fn decrypt_one_block_256(block: __m128i, round_keys: &[__m128i;15]) -> __m128i {

    let mut plaintext = unsafe { _mm_xor_si128(block, round_keys[14]) };
    for i in 1..14 {
        let round_key = unsafe { _mm_aesimc_si128(round_keys[14-i]) };
        plaintext = unsafe { _mm_aesdec_si128(plaintext, round_key) };
       
    }
    plaintext = unsafe { _mm_aesdeclast_si128(plaintext, round_keys[0]) };
    
    plaintext
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_array_align() {
        let mut vec:Vec<u8> = Vec::new();
        for _ in 0..16 {
            vec.push(0xFF);
            let aligned_vec = pkcs_pad16(&vec);
            println!("vec.len(): {}", vec.len());
            assert!(aligned_vec.len() == 16);
        }
    }


    #[test]
    fn test_key_expansion_256() {
        //these keys are from the official NIST AES standard
        let key: [u8; 32] = [
            0x60,0x3d,0xeb,0x10,
            0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,
            0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,
            0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,
            0x09,0x14,0xdf,0xf4,
        ];
        let official_expanded_key: [u32; 60] = [
            0x603deb10,
            0x15ca71be,
            0x2b73aef0,
            0x857d7781,
            0x1f352c07,
            0x3b6108d7,
            0x2d9810a3,
            0x0914dff4,
            0x9ba35411,
            0x8e6925af,
            0xa51a8b5f,
            0x2067fcde,
            0xa8b09c1a,
            0x93d194cd,
            0xbe49846e,
            0xb75d5b9a,
            0xd59aecb8,
            0x5bf3c917, 
            0xfee94248,
            0xde8ebe96,
            0xb5a9328a,
            0x2678a647,
            0x98312229,
            0x2f6c79b3,
            0x812c81ad,
            0xdadf48ba,
            0x24360af2,
            0xfab8b464,
            0x98c5bfc9,
            0xbebd198e,
            0x268c3ba7,
            0x09e04214,
            0x68007bac,
            0xb2df3316,
            0x96e939e4,
            0x6c518d80,
            0xc814e204,
            0x76a9fb8a,
            0x5025c02d,
            0x59c58239,
            0xde136967,
            0x6ccc5a71,
            0xfa256395,
            0x9674ee15,
            0x5886ca5d,
            0x2e2f31d7,
            0x7e0af1fa,
            0x27cf73c3,
            0x749c47ab,
            0x18501dda,
            0xe2757e4f,
            0x7401905a,
            0xcafaaae3,
            0xe4d59b34,
            0x9adf6ace,
            0xbd10190d,
            0xfe4890d1,
            0xe6188d0b,
            0x046df344,
            0x706c631e,

        ];
        let ekey = expand_key_256(&key);
        
        let mut x = [0u32;60];
        let mut i = 0;
        for block in ekey {
            let mut y = [0u8;16];
            unsafe { _mm_storeu_si128(y.as_mut_ptr() as *mut __m128i, block) };
            for j in 0..4 {
                x[i+j] = u32::from_be_bytes([y[4*j], y[4*j+1], y[4*j+2], y[4*j+3]]);
            }
            i += 4;
        }

        assert_eq!(x, official_expanded_key);

    }

    #[test]
    fn test_aes256_one_block() {
        let block: [u8;16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let key:   [u8;32] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];

        let exp:   [u8;16] = [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89];

        let round_keys = expand_key_256(&key);
        let input = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
        let encrypted = encrypt_one_block_256(input, &round_keys);
        assert_eq!(exp, simd_to_array(encrypted));
        let decrypted = decrypt_one_block_256(encrypted, &round_keys);
        assert_eq!(simd_to_array(decrypted), block);

    }
    
    #[test]
    fn test_ceildiv() {
        let a = 16;
        let b = 5;
        let c = 15;
        assert_eq!(3, ceildiv(c, b));
        assert_eq!(4, ceildiv(a, b))
    }

    #[test]
    fn test_LSB() {
        let a = 27;
        let b = 4;
        let c = LSB(a, b);
        println!("a: {:b}", a);
        println!("c: {:b}", c);
    }
}