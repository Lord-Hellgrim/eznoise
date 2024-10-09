#![allow(non_snake_case)]

use std::{error::Error, u64};

pub mod ezaes;

use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use ring;


/// A constant specifying the size in bytes of public keys and DH outputs. For security reasons, DHLEN must be 32 or greater.
pub const DHLEN: usize = 32;

pub struct KeyPair {
    public_key: PublicKey,
    private_key: EphemeralSecret,

}

#[derive(Debug, Clone)]
pub enum NoiseError {
    Ring(ring::error::Unspecified),
}

impl From<ring::error::Unspecified> for NoiseError {
    fn from(value: ring::error::Unspecified) -> Self {
        NoiseError::Ring(value)
    }
}


/// Generates a new Diffie-Hellman key pair. A DH key pair consists of public_key and private_key elements. 
/// A public_key represents an encoding of a DH public key into a byte sequence of length DHLEN. 
/// The public_key encoding details are specific to each set of DH functions.
pub fn GENERATE_KEYPAIR() -> KeyPair {
    let private_key = EphemeralSecret::random();
    let public_key = PublicKey::from(&private_key);
    
    KeyPair {
        public_key,
        private_key,
    }
}


/// Performs a Diffie-Hellman calculation between the private key in key_pair and the public_key 
/// and returns an output sequence of bytes of length DHLEN. 
/// For security, the Gap-DH problem based on this function must be unsolvable by any practical cryptanalytic adversary [2].

/// The public_key either encodes some value which is a generator in a large prime-order group 
/// (which value may have multiple equivalent encodings), or is an invalid value. 
/// Implementations must handle invalid public keys either by returning some output which is purely a function of the public key 
/// and does not depend on the private key, or by signaling an error to the caller. 
/// The DH function may define more specific rules for handling invalid values.
pub fn DH(key_pair: KeyPair, public_key: PublicKey) -> SharedSecret {
    
    key_pair.private_key.diffie_hellman(&public_key)
} 


/// Encrypts plaintext using the cipher key k of 32 bytes and an 8-byte unsigned integer nonce n which must be unique for the key k. 
/// Returns the ciphertext. Encryption must be done with an "AEAD" encryption mode with the associated data ad 
/// (using the terminology from [1]) and returns a ciphertext that is the same size as the plaintext plus 16 bytes for authentication data. 
/// The entire ciphertext must be indistinguishable from random if the key is secret 
/// (note that this is an additional requirement that isn't necessarily met by all AEAD schemes).
pub fn ENCRYPT(k: [u8;32], n: u64, ad: &[u8], plaintext: &mut Vec<u8>) -> Result<(), NoiseError> {

    let nonce = nonce_from_u64(n);
    let key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &k).expect("THE KEY SHOULD NOT FAIL");
    let key = ring::aead::LessSafeKey::new(key);
    let ad = ring::aead::Aad::from(ad);
    match key.seal_in_place_append_tag(nonce, ad, plaintext) {
        Ok(_) => {
            
            Ok(())
        },
        Err(e) => Err(NoiseError::from(e)),
    }
}

pub fn nonce_from_u64(n: u64) -> ring::aead::Nonce {
    let n = n.to_be_bytes();
    ring::aead::Nonce::assume_unique_for_key([0,0,0,0,n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]])
}

/// Decrypts ciphertext using a cipher key k of 32 bytes, an 8-byte unsigned integer nonce n,
/// and associated data ad. Returns the plaintext, unless authentication fails, 
/// in which case an error is signaled to the caller.
pub fn DECRYPT<'inout>(k: [u8;32], n: ring::aead::Nonce, ad: &[u8], ciphertext: &'inout mut Vec<u8>) -> Result<&'inout [u8], NoiseError>{
    
    let key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &k).expect("THE KEY SHOULD NOT FAIL");
    let key = ring::aead::LessSafeKey::new(key);
    let ad = ring::aead::Aad::from(ad);
    match key.open_in_place(n, ad, ciphertext) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => Err(NoiseError::from(e)),
    }
}

/// Hashes some arbitrary-length data with a collision-resistant cryptographic hash function and returns an output of HASHLEN bytes.
pub fn HASH(data: &[u8]) -> [u8;32] {
    let digest = ring::digest::digest(&ring::digest::SHA512, data);
    let mut hash = [0u8;32];
    hash.copy_from_slice(digest.as_ref());
    hash

}

/// A constant specifying the size in bytes of the hash output. Must be 32 or 64.
pub const HASHLEN: usize = 32;

/// A constant specifying the size in bytes that the hash function uses internally to divide its input for iterative processing. 
/// This is needed to use the hash function with HMAC (BLOCKLEN is B in [3]).
pub const BLOCKLEN: usize = 64;

/// Creates a usize from a &[u8] of length 8. Panics if len is different than 8.
#[inline]
pub fn u64_from_le_slice(slice: &[u8]) -> usize {   
    #[cfg(debug_assertions)]
    println!("calling: usize_from_le_slice()");

    assert!(slice.len() >= 8);
    let l: [u8;8] = [slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7]];
    usize::from_le_bytes(l)
}


/// Returns a new 32-byte cipher key as a pseudorandom function of k. If this function is not specifically defined for some set of cipher functions, 
/// then it defaults to returning the first 32 bytes from ENCRYPT(k,    maxnonce, zerolen, zeros), 
/// where maxnonce equals 264-1, zerolen is a zero-length byte sequence, and zeros is a sequence of 32 bytes filled with zeros.
pub fn REKEY(k: [u8;32]) -> [u8;32] {
    let mut zeros = Vec::from([0u8;32]);
    let n = u64::MAX;
    let zerolen: &[u8] = &[];
    ENCRYPT(k, n, zerolen, &mut zeros).expect("THE REKEY FUNCTION SHOULD NEVER FAIL");
    let mut new_key = [0u8;32];
    new_key.copy_from_slice(&zeros[0..32]);
    new_key
}


pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn encrypt_and_decrypt() {
        let k = [0u8;32];
        let n = 5;
        let ad = "Double check me".as_bytes();
        let unencrypted = "This is an unencrypted block of text that is longer than 128 bits!!!";
        let mut buffer = Vec::from(unencrypted.to_owned());
        ENCRYPT(k, n, ad, &mut buffer).unwrap();
        let n = nonce_from_u64(n);
        let decrypted = DECRYPT(k, n, ad, &mut buffer).unwrap();
        assert_eq!(unencrypted.as_bytes(), decrypted);
    }

    #[test]
    fn test_rekey() {
        let mut k = [0u8;32];
        let mut map = HashMap::new();
        for _ in 0..10000 {
            let nk = REKEY(k);
            map.insert(k, nk);
            k = nk;
        }

        let mut k = [0u8;32];
        for _ in 0..10000 {
            let nk = REKEY(k);
            assert_eq!(map.get(&k).unwrap(), &nk);
            k = nk;
        }
        
    }
}
