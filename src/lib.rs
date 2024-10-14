#![allow(non_snake_case)]
#![feature(concat_bytes)]
#![feature(portable_simd)]

use std::{io::Write, u64};
use std::io::Read;

use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use ring;


/// A constant specifying the size in bytes of public keys and DH outputs. For security reasons, DHLEN must be 32 or greater.
pub const DHLEN: usize = 32;
/// A constant specifying the size in bytes of the hash output. Must be 32 or 64.
pub const HASHLEN: usize = 32;

/// A constant specifying the size in bytes that the hash function uses internally to divide its input for iterative processing. 
/// This is needed to use the hash function with HMAC (BLOCKLEN is B in [3]).
pub const BLOCKLEN: usize = 128;
/// The HMAC padding strings
pub const IPAD: [u8;BLOCKLEN] = [0x36;BLOCKLEN];
pub const OPAD: [u8;BLOCKLEN] = [0x5c;BLOCKLEN];

pub const PROTOCOL_NAME: &'static str = "Noise_NK_25519_AESGCM_SHA512";

#[derive(Clone)]
pub struct KeyPair {
    public_key: Option<[u8;32]>,
    private_key: Option<[u8;32]>,

}

#[derive(Debug, Clone)]
pub enum NoiseError {
    Ring,
    WrongState,
    Io,
}

impl From<ring::error::Unspecified> for NoiseError {
    fn from(_value: ring::error::Unspecified) -> Self {
        NoiseError::Ring
    }
}

impl From<std::io::Error> for NoiseError {
    fn from(_value: std::io::Error) -> Self {
        NoiseError::Io
    }
}


/// Generates a new Diffie-Hellman key pair. A DH key pair consists of public_key and private_key elements. 
/// A public_key represents an encoding of a DH public key into a byte sequence of length DHLEN. 
/// The public_key encoding details are specific to each set of DH functions.
pub fn GENERATE_KEYPAIR() -> KeyPair {
    let private_key = x25519_dalek::StaticSecret::random();
    let public_key = PublicKey::from(&private_key).to_bytes();
    
    KeyPair {
        public_key: Some(public_key),
        private_key: Some(private_key.to_bytes()),
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
pub fn DH(key_pair: KeyPair, public_key: PublicKey) -> [u8;32] {
    assert!(key_pair.private_key.is_some() && key_pair.public_key.is_some());
    let pkey = StaticSecret::from(key_pair.private_key.unwrap());
    pkey.diffie_hellman(&public_key).to_bytes()
} 


/// Encrypts plaintext using the cipher key k of 32 bytes and an 8-byte unsigned integer nonce n which must be unique for the key k. 
/// Returns the ciphertext. Encryption must be done with an "AEAD" encryption mode with the associated data ad 
/// (using the terminology from [1]) and returns a ciphertext that is the same size as the plaintext plus 16 bytes for authentication data. 
/// The entire ciphertext must be indistinguishable from random if the key is secret 
/// (note that this is an additional requirement that isn't necessarily met by all AEAD schemes).
pub fn ENCRYPT<'inout>(k: [u8;HASHLEN], n: u64, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {

    let nonce = nonce_from_u64(n);
    let key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &k).expect("THE KEY SHOULD NOT FAIL");
    let key = ring::aead::LessSafeKey::new(key);
    let ad = ring::aead::Aad::from(ad);
    let mut output_buffer = plaintext.to_vec();
    match key.seal_in_place_append_tag(nonce, ad, &mut output_buffer) {
        Ok(_) => {
            
            Ok(output_buffer)
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
pub fn DECRYPT<'inout>(k: [u8;HASHLEN], n: u64, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError>{
    
    let nonce = nonce_from_u64(n);
    let key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &k).expect("THE KEY SHOULD NOT FAIL");
    let key = ring::aead::LessSafeKey::new(key);
    let ad = ring::aead::Aad::from(ad);
    let mut output_buffer = ciphertext.to_vec();

    match key.open_in_place(nonce, ad, &mut output_buffer) {
        Ok(x) => Ok(output_buffer),
        Err(e) => Err(NoiseError::from(e)),
    }
}

/// Hashes some arbitrary-length data with a collision-resistant cryptographic hash function and returns an output of HASHLEN bytes.
pub fn HASH(data: &[u8]) -> [u8;HASHLEN] {
    let digest = ring::digest::digest(&ring::digest::SHA512, data);
    let mut hash = [0u8;HASHLEN];
    hash.copy_from_slice(digest.as_ref());
    hash

}


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
pub fn REKEY(k: [u8;HASHLEN]) -> [u8;HASHLEN] {
    let mut zeros = Vec::from([0u8;HASHLEN]);
    let n = u64::MAX;
    let zerolen: &[u8] = &[];
    ENCRYPT(k, n, zerolen, &mut zeros).expect("THE REKEY FUNCTION SHOULD NEVER FAIL");
    let mut new_key = [0u8;HASHLEN];
    new_key.copy_from_slice(&zeros[0..HASHLEN]);
    new_key
}

pub fn HMAC_HASH(K: [u8;HASHLEN], text: &[u8]) -> [u8;HASHLEN] {
    let K = zeropad128(&K);
    let inner: [u8;HASHLEN] = HASH(&concat_bytes(&array_xor(K, IPAD), text));
    let outer: [u8;HASHLEN] = HASH(&concat_bytes(&array_xor(K, OPAD), &inner));
    outer
}

/// Takes a chaining_key byte sequence of length HASHLEN, and an input_key_material byte sequence with length either zero bytes, 
/// 32 bytes, or DHLEN bytes. Returns a pair or triple of byte sequences each of length HASHLEN, depending on whether num_outputs is two or three:
///  - Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
///  - Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
///  - Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
///  - If num_outputs == 2 then returns the pair (output1, output2).
///  - Sets output3 = HMAC-HASH(temp_key, output2 || byte(0x03)).
///  - Returns the triple (output1, output2, output3).
///  - Note that temp_key, output1, output2, and output3 are all HASHLEN bytes in length. Also note that the HKDF() function is simply HKDF from [4] with the chaining_key as HKDF salt, and zero-length HKDF info.
pub fn HKDF(chaining_key: [u8;HASHLEN], input_key_material: &[u8]) -> ([u8;HASHLEN], [u8;HASHLEN], [u8;HASHLEN]) {
    assert!(input_key_material.len() == 0 || input_key_material.len() == 32);
    let temp_key = HMAC_HASH(chaining_key, &input_key_material);
    let output1 = HMAC_HASH(temp_key, &[0x01]);
    let output2 = HMAC_HASH(temp_key, &concat_bytes(&output1, &[0x02]));
    let output3 = HMAC_HASH(temp_key, &concat_bytes(&output2, &[0x03]));

    (output1, output2, output3)
} 


pub fn array_xor(a: [u8; BLOCKLEN], b: [u8; BLOCKLEN]) -> [u8;BLOCKLEN] {
    let mut output = [0u8;BLOCKLEN];
    for i in 0..8 {
        let blocka = std::simd::u8x16::from_slice(&a[i*16..i*16+16]);
        let blockb = std::simd::u8x16::from_slice(&b[i*16..i*16+16]);
        output[i*16..i*16+16].copy_from_slice((blocka ^blockb).as_array());
    }

    output
        

}

pub fn zeropad128(input: &[u8]) -> [u8;BLOCKLEN]{
    assert!(input.len() <= BLOCKLEN);
    let mut output = [0u8;BLOCKLEN];
    output[0..input.len()].copy_from_slice(input);
    output
}

pub fn zeropad32(input: &[u8]) -> [u8;HASHLEN]{
    assert!(input.len() <= HASHLEN);
    let mut output = [0u8;HASHLEN];
    output[0..input.len()].copy_from_slice(input);
    output
}

pub fn concat_bytes(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(b1.len() + b2.len());
    output.extend_from_slice(b1);
    output.extend_from_slice(b2);
    output
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}


#[allow(non_camel_case_types)]
pub enum Token {
    e,
    s,
    ee,
    es,
    se,
    ss,
}

pub struct CipherState {
    k: Option<[u8;HASHLEN]>,
    n: u64,
}

pub struct SymmetricState {
    cipherstate: CipherState,
    ck: [u8;HASHLEN],
    h: [u8; HASHLEN]
}

pub struct HandshakeState {
    symmetricstate: SymmetricState,
    s: KeyPair,
    e: KeyPair, 
    rs: Option<PublicKey>,
    re: Option<PublicKey>,
    initiator: bool,
    message_patterns: Vec<Vec<Token>>
}

impl CipherState {

    /// Sets k = key. Sets n = 0.
    pub fn InitializeKey(key: Option<[u8;32]>) -> CipherState {
        CipherState {
            k: key,
            n: 0
        }
    }

    /// Returns true if k is non-empty, false otherwise.
    pub fn HasKey(&self) -> bool {
        self.k.is_some()
    }

    /// Sets n = nonce. This function is used for handling out-of-order transport messages, as described in Section 11.4.
    pub fn SetNonce(&mut self, nonce: u64) {
        self.n = nonce
    }

    ///If k is non-empty returns ENCRYPT(k, n++, ad, plaintext). Otherwise returns plaintext.
    pub fn EncryptWithAd(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        if self.HasKey() {
            self.n += 1;
            ENCRYPT(self.k.unwrap(), self.n, ad, plaintext).unwrap()
        } else {
            plaintext.to_vec()
        }
    }

    /// If k is non-empty returns DECRYPT(k, n++, ad, ciphertext). Otherwise returns ciphertext. 
    /// If an authentication failure occurs in DECRYPT() then n is not incremented and an error is signaled to the caller.
    pub fn DecryptWithAd(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.HasKey() {
            let temp_n = self.n+1;
            let plaintext = DECRYPT(self.k.unwrap(), temp_n, ad, ciphertext)?;
            self.n += 1;
            Ok(plaintext)
        } else {
            Ok(ciphertext.to_vec())
        }
    }

    /// Sets k = REKEY(k).
    pub fn Rekey(&mut self) {
        match self.k {
            Some(k) => self.k = Some(REKEY(k)),
            None => ()
        }
    }
}

impl SymmetricState {

    /// : Takes an arbitrary-length protocol_name byte sequence (see Section 8). Executes the following steps:
    
    /// If protocol_name is less than or equal to HASHLEN bytes in length, sets h equal to protocol_name with zero bytes appended to make HASHLEN bytes. Otherwise sets h = HASH(protocol_name).
    
    /// Sets ck = h.
    
    /// Calls InitializeKey(empty).
    pub fn InitializeSymmetric(protocol_name: &str) -> SymmetricState {
        if protocol_name.len() < 32 {
            let h = HASH(&zeropad32(protocol_name.as_bytes()));
            let cipherstate = CipherState::InitializeKey(None);
            SymmetricState {
                cipherstate,
                ck: h,
                h: h,
            }
        } else {
            let h = HASH(&protocol_name.as_bytes());
            let cipherstate = CipherState::InitializeKey(None);
            SymmetricState {
                cipherstate,
                ck: h,
                h: h,
            }
        }
    }

    /// Sets h = HASH(h || data).
    pub fn MixHash(&mut self, data: &[u8]) {
        self.h = HASH(&concat_bytes(&self.h, data));
    }

    ///     : Executes the following steps:

    /// Sets ck, temp_k = HKDF(ck, input_key_material, 2).
    /// If HASHLEN is 64, then truncates temp_k to 32 bytes.
    /// Calls InitializeKey(temp_k).
    pub fn MixKey(&mut self, input_key_material: [u8;32]) {
        let (ck, temp_k, _) = HKDF(self.ck, &input_key_material);
        self.ck = ck;
        self.cipherstate = CipherState::InitializeKey(Some(temp_k));
    }

    /// This function is used for handling pre-shared symmetric keys, as described in Section 9. It executes the following steps:
    
    /// Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
    /// Calls MixHash(temp_h).
    /// If HASHLEN is 64, then truncates temp_k to 32 bytes.
    /// Calls InitializeKey(temp_k).
    pub fn MixKeyAndHash(&mut self, input_key_material: [u8;32]) {
        let (ck, temp_h, temp_k) = HKDF(self.ck, &input_key_material);
        self.ck = ck;
        self.MixHash(&temp_h);
        self.cipherstate = CipherState::InitializeKey(Some(temp_k));
    }

    /// Returns h. This function should only be called at the end of a handshake, i.e. after the Split() function has been called. 
    /// This function is used for channel binding, as described in Section 11.2
    pub fn GetHandshakeHash(&self) -> [u8;32] {
        self.h
    }

    /// Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. 
    /// Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
    pub fn EncryptAndHash(&mut self, plaintext: &[u8]) -> Vec<u8>{
        let ciphertext = self.cipherstate.EncryptWithAd(&self.h, plaintext);
        self.MixHash(&plaintext);
        ciphertext
    }

    /// Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext. 
    /// Note that if k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.
    pub fn DecryptAndHash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let result = self.cipherstate.DecryptWithAd(&self.h, ciphertext);
        self.MixHash(ciphertext);
        result
    }

    /// Returns a pair of CipherState objects for encrypting transport messages. Executes the following steps, where zerolen is a zero-length byte sequence:
    /// Sets temp_k1, temp_k2 = HKDF(ck, zerolen, 2).
    /// If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.
    /// Creates two new CipherState objects c1 and c2.
    /// Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
    /// Returns the pair (c1, c2).
    pub fn Split(&self) -> (CipherState, CipherState) {
        let (temp_k1, temp_k2, _) = HKDF(self.ck, &[]);
        let c1 = CipherState::InitializeKey(Some(temp_k1));
        let c2 = CipherState::InitializeKey(Some(temp_k2));
        (c1, c2)
    }
}

impl HandshakeState {
    /// : Takes a valid handshake_pattern (see Section 7) and an initiator boolean specifying this party's role as either initiator or responder.
    
    /// Takes a prologue byte sequence which may be zero-length, or which may contain context information that both parties want to confirm is identical 
    /// (see Section 6).
    
    /// Takes a set of DH key pairs (s, e) and public keys (rs, re) for initializing local variables, any of which may be empty. 
    /// Public keys are only passed in if the handshake_pattern uses pre-messages (see Section 7). The ephemeral values (e, re) are typically left empty, 
    /// since they are created and exchanged during the handshake; but there are exceptions (see Section 10).
    
    /// Performs the following steps:
    
    /// Derives a protocol_name byte sequence by combining the names for the handshake pattern and crypto functions, as specified in Section 8. 
    /// Calls InitializeSymmetric(protocol_name).
    
    /// Calls MixHash(prologue).
    
    /// Sets the initiator, s, e, rs, and re variables to the corresponding arguments.
    
    /// Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern, 
    /// with the specified public key as input (see Section 7 for an explanation of pre-messages). 
    /// If both initiator and responder have pre-messages, the initiator's public keys are hashed first. 
    /// If multiple public keys are listed in either party's pre-message, the public keys are hashed in the order that they are listed.
    
    /// Sets message_patterns to the message patterns from handshake_pattern.
    pub fn Initialize(
        initiator: bool,
        prologue: &[u8],
        s: KeyPair,
        e: KeyPair,
        rs: Option<PublicKey>,
        re: Option<PublicKey>
    ) -> HandshakeState {
        let pre_message_pattern = [Token::s];
        let handshake_pattern_NK = vec![vec![Token::e, Token::es], vec![Token::e, Token::ee]];

        let mut symmetricstate = SymmetricState::InitializeSymmetric(&PROTOCOL_NAME);
        symmetricstate.MixHash(prologue);
        let mut output = HandshakeState {
            symmetricstate,
            s,
            e,
            rs,
            re,
            initiator,
            message_patterns: handshake_pattern_NK,
        };

        output.symmetricstate.MixHash(&output.s.public_key.expect("I expect there will always be a public key here"));
        output
    }

    /// Takes a payload byte sequence which may be zero-length, and a message_buffer to write the output into. 
    /// Performs the following steps, aborting if any EncryptAndHash() call returns an error:
    
    /// Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token from the message pattern:
    
    /// For "e": Sets e (which must be empty) to GENERATE_KEYPAIR(). Appends e.public_key to the buffer. Calls MixHash(e.public_key).
    
    /// For "s": Appends EncryptAndHash(s.public_key) to the buffer.
    
    /// For "ee": Calls MixKey(DH(e, re)).
    
    /// For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
    
    /// For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
    
    /// For "ss": Calls MixKey(DH(s, rs)).
    
    /// Appends EncryptAndHash(payload) to the buffer.
    
    /// If there are no more message patterns returns two new CipherState objects by calling Split().
    pub fn WriteMessage(&mut self, payload: &[u8], mut message_buffer: impl Write) -> Result<(), NoiseError> {

        let pattern = self.message_patterns.remove(0);
        for token in pattern {
            match token {
                Token::e => {
                    self.e = GENERATE_KEYPAIR();
                    message_buffer.write_all(&self.e.public_key.unwrap())?;
                    self.symmetricstate.MixHash(&self.e.public_key.unwrap());
                },
                Token::s => {
                    let temp = self.symmetricstate.EncryptAndHash(&self.s.public_key.unwrap());
                    message_buffer.write_all(&temp)?;
                },
                
                Token::ee => self.symmetricstate.MixKey(DH(self.e.clone(), self.re.unwrap())),

                Token::es => self.symmetricstate.MixKey(DH(self.e.clone(), self.rs.unwrap())),
                
                Token::se => self.symmetricstate.MixKey(DH(self.s.clone(), self.re.unwrap())),
                
                Token::ss => self.symmetricstate.MixKey(DH(self.s.clone(), self.rs.unwrap())),
            };
        }
        let ciphertext = self.symmetricstate.EncryptAndHash(payload);
        message_buffer.write_all(&ciphertext)?;

        Ok(())
    }

    /// Takes a byte sequence containing a Noise handshake message, and a payload_buffer to write the message's plaintext payload into. 
    /// Performs the following steps, aborting if any DecryptAndHash() call returns an error:
    
    /// Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token from the message pattern:
    
    /// For "e": Sets re (which must be empty) to the next DHLEN bytes from the message. Calls MixHash(re.public_key).
    
    /// For "s": Sets temp to the next DHLEN + 16 bytes of the message if HasKey() == True, or to the next DHLEN bytes otherwise. 
    /// Sets rs (which must be empty) to DecryptAndHash(temp).
    
    /// For "ee": Calls MixKey(DH(e, re)).
    
    /// For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
    
    /// For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
    
    /// For "ss": Calls MixKey(DH(s, rs)).
    
    /// Calls DecryptAndHash() on the remaining bytes of the message and stores the output into payload_buffer.
    
    /// If there are no more message patterns returns two new CipherState objects by calling Split().
    pub fn ReadMessage(&mut self, mut message: impl Read, payload_buffer: &mut Vec<u8>)  -> Result<(CipherState, CipherState), NoiseError> {
        let pattern = self.message_patterns.remove(0);
        for token in pattern {
            match token {
                Token::e => {
                    let mut e = [0u8;DHLEN];
                    message.read_exact(&mut e)?;
                    if self.re.is_none() {
                        self.re = None;
                        return Err(NoiseError::WrongState);
                    } else {
                        self.re = Some(PublicKey::from(e));
                    }
                },
                Token::s => {
                    if self.symmetricstate.cipherstate.HasKey() {
                        let mut temp = [0u8;DHLEN+16];
                        message.read_exact(&mut temp)?;
                        let temp = array32_from_slice(&self.symmetricstate.DecryptAndHash(&temp)?);
                        if self.rs.is_none() {
                            self.rs = Some(PublicKey::from(temp));
                        } else {
                            return Err(NoiseError::WrongState)
                        }
                    }
                },
                
                Token::ee => self.symmetricstate.MixKey(DH(self.e.clone(), self.re.unwrap())),

                Token::es => {
                    if self.initiator {
                        self.symmetricstate.MixKey(DH(self.e.clone(), self.rs.unwrap()));  
                    } else {
                        self.symmetricstate.MixKey(DH(self.s.clone(), self.re.unwrap()));
                    }
                },
                
                Token::se => {
                    if self.initiator {
                        self.symmetricstate.MixKey(DH(self.s.clone(), self.re.unwrap()));  
                    } else {
                        self.symmetricstate.MixKey(DH(self.e.clone(), self.rs.unwrap()));
                    }
                },
                
                Token::ss => self.symmetricstate.MixKey(DH(self.s.clone(), self.rs.unwrap())),
            };
            let mut buf = Vec::new();
            message.read_to_end(&mut buf)?;
            payload_buffer.extend_from_slice(&buf);
        }
        let (c1, c2) = self.symmetricstate.Split();
        Ok((c1, c2))
    }
}

pub fn array32_from_slice(slice: &[u8]) -> [u8;32] {
    assert!(slice.len() > 32);
    let mut buf = [0u8;32];
    buf.copy_from_slice(&slice[0..32]);
    buf
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
        let mut encrypted = ENCRYPT(k, n, ad, &mut buffer).unwrap();
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

    #[test]
    fn protocol_name_length() {
        println!("{}", PROTOCOL_NAME.len());
    }
}
