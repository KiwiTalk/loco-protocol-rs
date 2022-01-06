/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use byteorder::{LittleEndian, ReadBytesExt};

use libaes::Cipher;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use crate::secure::{SecureHandshake, SecureHandshakeHeader};
use crate::Error;
use serde_repr::*;

#[repr(u32)]
#[derive(Debug, Serialize_repr, Deserialize_repr, Copy, Clone)]
pub enum EncryptType {
    AesCfb128 = 2,
}

#[repr(u32)]
#[derive(Debug, Serialize_repr, Deserialize_repr, Copy, Clone)]
pub enum KeyEncryptType {
    RsaOaepSha1Mgf1Sha1 = 12,
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Corrupted Data")]
    CorruptedData,
}


/// AES Crypto implementation using aes
#[derive(Clone, Debug)]
pub struct CryptoStore {
    aes_key: [u8; 16],
    rng: OsRng,
}

impl CryptoStore {
    /// Create new crypto using cryptographically secure random key
    pub fn new() -> Self {
        let mut aes_key = [0_u8; 16];
        let mut rng = OsRng::default();

        rng.fill_bytes(&mut aes_key);

        Self {
            aes_key,
            rng,
        }
    }

    /// Create new crypto store using given AES key
    pub fn new_with_key(aes_key: [u8; 16]) -> Self {
        Self {
            aes_key,
            rng: OsRng::default(),
        }
    }

    pub fn encrypt_aes(&self, data: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Cipher::new_128(&self.aes_key);

        Ok(cipher.cfb128_encrypt(iv, data))
    }

    pub fn decrypt_aes(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Cipher::new_128(&self.aes_key);

        Ok(cipher.cfb128_decrypt(iv, data))
    }

    /// Encrypt AES key using RSA public key
    pub fn encrypt_key(&mut self, key: &RsaPublicKey) -> Result<Vec<u8>, CryptoError> {
        Ok(key
            .encrypt(
                &mut self.rng,
                PaddingScheme::new_oaep::<sha1::Sha1>(),
                &self.aes_key,
            )
            .unwrap())
    }

    pub fn gen_random(&mut self, data: &mut [u8]) {
        self.rng.fill_bytes(data);
    }
}


pub(super) fn to_handshake_packet(
    crypto: &mut CryptoStore,
    key: &RsaPublicKey,
) -> Result<Vec<u8>, Error> {
    let encrypted_key = crypto.encrypt_key(key)?;

    let handshake_header = SecureHandshakeHeader {
        key_encrypt_type: KeyEncryptType::RsaOaepSha1Mgf1Sha1,
        encrypt_type: EncryptType::AesCfb128,
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
pub(super) fn decode_handshake_head(mut buf: &[u8]) -> Result<SecureHandshake, Error> {
    let key_size = buf.read_u32::<LittleEndian>()?;
    let header: SecureHandshakeHeader =
        bincode::deserialize_from(&mut buf)?;

    Ok(SecureHandshake {
        header,
        encrypted_key: vec![0_u8; key_size as usize],
    })
}

