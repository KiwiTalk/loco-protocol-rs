/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use loco_protocol::secure::crypto::{CryptoStore, EncryptType, KeyEncryptType};
use loco_protocol::secure::{SecureHandshakeHeader, SecureStreamRead};
/*
#[test]
pub fn handshake() {
    let private_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    let crypto = CryptoStore::new();

    let mut local = Vec::<u8>::new();

    let mut client_session = SecureStreamRead::new(crypto, &mut local);

    client_session.write_handshake(&public_key).expect("Client handshake failed");

    SecureStreamRead::read_handshake(&*local, &private_key).expect("Server handshake failed");
}
*/
#[test]
pub fn handshake_header() {
    let handshake_header = SecureHandshakeHeader {
        key_encrypt_type: KeyEncryptType::RsaOaepSha1Mgf1Sha1,
        encrypt_type: EncryptType::AesCfb128,
    };
    let header_data = bincode::serialize(&handshake_header).unwrap();
    println!("{:?}", header_data)
}