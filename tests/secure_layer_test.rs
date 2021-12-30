/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::{Cursor, Read, Write};
use loco_protocol::secure::crypto::CryptoStore;
use loco_protocol::secure::SecureStream;


#[test]
pub fn secure_layer_read_write() {
    let mut local = Vec::<u8>::new();

    let crypto = CryptoStore::new();
    let mut stream = SecureStream::new(crypto.clone(), Cursor::new(&mut local));

    let test_data1 = vec![1_u8, 2, 3, 4];
    let test_data2 = vec![1_u8, 2, 3, 4];

    stream
        .write(&test_data1)
        .expect("Data writing must not fail");
    stream
        .write(&test_data2)
        .expect("Data writing must not fail");

    let mut inner = stream.into_inner();
    inner.set_position(0);

    let mut stream = SecureStream::new(crypto, inner);
    let mut reader = [0; 4];

    stream.read(&mut reader).expect("Data reading must not fail");
    assert_eq!(reader, *test_data1);

    stream.read(&mut reader).expect("Data reading must not fail");
    assert_eq!(reader, *test_data2);
}
