/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use loco_protocol::secure::crypto::CryptoStore;
use loco_protocol::secure::SecureStream;

#[test]
pub fn handshake() {
    let private_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    let aes_key = "1234123412341234";

    let local = Vec::<u8>::new();

    let mut client_session = SecureStream::new(CryptoStore::new_with_key(aes_key.as_bytes().try_into().unwrap()), local);

    client_session.write_handshake(&public_key).expect("Client handshake failed");

    let mut local = client_session.into_inner();

    SecureStream::read_handshake(&*local, &private_key).expect("Server handshake failed");
}
