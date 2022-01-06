/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::{Cursor, Read, Write};
use loco_protocol::secure::crypto::CryptoStore;
use loco_protocol::secure::{SecureStreamRead, SecureStreamWrite};


#[test]
pub fn secure_stream_read_write() {
    let mut local = Vec::<u8>::new();

    let crypto = CryptoStore::new_with_key([1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4]);
    let mut stream = SecureStreamWrite::new(crypto.clone(), Cursor::new(&mut local));

    let test_data = vec![1_u8, 2, 3, 4];

    stream
        .write_all(&test_data)
        .expect("Data writing must not fail");

    // Reset read/write position
    let mut inner = stream.into_inner();
    inner.set_position(0);

    let mut stream = SecureStreamRead::new(crypto, inner);

    let mut data = vec![0_u8; 4];

    stream.read_exact(&mut data).expect("Data reading must not fail");

    assert_eq!(test_data, data);
}
