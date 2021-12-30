/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::{cell::RefCell, fmt::Display};
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};

use libaes::Cipher;
use rand::{prelude::ThreadRng, rngs, RngCore};
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use crate::secure::{SECURE_HANDSHAKE_HEAD_SIZE, SecureHandshake, SecureHandshakeHeader};
use crate::Error;

#[repr(u32)]
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub enum EncryptType {
    AesCfb128 = 2,
}

#[repr(u32)]
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub enum KeyEncryptType {
    RsaOaepSha1Mgf1Sha1 = 12,
}

#[derive(Debug)]
pub enum CryptoError {
    CorruptedData,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Corrupted data")
    }
}


/// AES Crypto implementation using aes
#[derive(Clone, Debug)]
pub struct CryptoStore {
    aes_key: [u8; 16],
    rng: RefCell<ThreadRng>,
}

impl CryptoStore {
    /// Create new crypto using cryptographically secure random key
    pub fn new() -> Self {
        let mut aes_key = [0_u8; 16];
        let mut rng = rngs::ThreadRng::default();

        rng.fill_bytes(&mut aes_key);

        Self {
            aes_key,
            rng: RefCell::new(rng),
        }
    }

    /// Create new crypto store using given AES key
    pub fn new_with_key(aes_key: [u8; 16]) -> Self {
        Self {
            aes_key,
            rng: RefCell::new(rngs::ThreadRng::default()),
        }
    }

    pub fn encrypt_aes(&self, data: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Cipher::new_128(&self.aes_key);

        Ok(cipher.cfb128_encrypt(iv, data))
    }

    pub fn decrypt_aes(&self, data: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Cipher::new_128(&self.aes_key);

        Ok(cipher.cfb128_decrypt(iv, data))
    }

    /// Encrypt AES key using RSA public key
    pub fn encrypt_key(&self, key: &RsaPublicKey) -> Result<Vec<u8>, CryptoError> {
        Ok(key
            .encrypt(
                (&mut self.rng.borrow_mut()) as &mut ThreadRng,
                PaddingScheme::new_oaep::<sha1::Sha1>(),
                &self.aes_key,
            )
            .unwrap())
    }

    pub fn gen_random(&self, data: &mut [u8]) {
        self.rng.borrow_mut().fill_bytes(data);
    }
}


pub(super) fn to_handshake_packet(
    crypto: &CryptoStore,
    key: &RsaPublicKey,
) -> Result<Vec<u8>, Error> {
    let encrypted_key = crypto.encrypt_key(key)?;

    let handshake_header = SecureHandshakeHeader {
        key_encrypt_type: KeyEncryptType::RsaOaepSha1Mgf1Sha1 as u32,
        encrypt_type: EncryptType::AesCfb128 as u32,
    };
    let header_data = bincode::serialize(&handshake_header)?;

    Ok([
        (encrypted_key.len() as u32).to_le_bytes().into(),
        header_data,
        encrypted_key,
    ]
        .concat())
}

/// Decode key_size and [SecureHandshakeHeader] into empty [SecureHandshake].
pub(super) fn decode_handshake_head(buf: &[u8]) -> Result<SecureHandshake, Error> {
    let key_size = Cursor::new(&buf[..4]).read_u32::<LittleEndian>()?;
    let header =
        bincode::deserialize::<SecureHandshakeHeader>(&buf[4..SECURE_HANDSHAKE_HEAD_SIZE])?;

    Ok(SecureHandshake {
        header,
        encrypted_key: vec![0_u8; key_size as usize],
    })
}

