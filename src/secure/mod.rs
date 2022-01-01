/*
 * Created on Sat Nov 28 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use serde::{Deserialize, Serialize};

pub mod crypto;

mod secure_stream;

pub use secure_stream::*;
use crate::secure::crypto::{EncryptType, KeyEncryptType};

pub const SECURE_HEAD_SIZE: usize = SECURE_HEADER_SIZE + 4;
pub const SECURE_HEADER_SIZE: usize = 16;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SecureHeader {
    pub iv: [u8; 16],
}

#[derive(Debug)]
pub struct SecurePacket {
    pub header: SecureHeader,
    pub data: Vec<u8>,
}

pub const SECURE_HANDSHAKE_HEAD_SIZE: usize = SECURE_HANDSHAKE_HEADER_SIZE + 4;
pub const SECURE_HANDSHAKE_HEADER_SIZE: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureHandshakeHeader {
    pub key_encrypt_type: KeyEncryptType,
    pub encrypt_type: EncryptType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureHandshake {
    pub header: SecureHandshakeHeader,
    pub encrypted_key: Vec<u8>,
}
