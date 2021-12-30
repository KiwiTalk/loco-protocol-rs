/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::Cursor;

use loco_protocol::command::{loco_command_codec::CommandCodec, LocoCommand, LocoHeader, ReadLocoCommand, WriteLocoCommand};

#[test]
pub fn codec_read_write() {
    let mut local = Vec::<u8>::new();

    let test_command1 = LocoCommand {
        header: LocoHeader {
            id: 0,
            data_type: 0,
            status: 0,
            method: "TEST1".into(),
        },
        data: vec![0_u8; 4],
    };

    let test_command2 = LocoCommand {
        header: LocoHeader {
            id: 0,
            data_type: 0,
            status: 0,
            method: "TEST2".into(),
        },
        data: vec![8_u8; 4],
    };


    local.write_loco_command(&test_command1)
        .expect("Command write must not fail");

    local.write_loco_command(&test_command2)
        .expect("Command write must not fail");

    let mut read_codec = Cursor::new(&mut local);

    let command1 = read_codec.read_loco_command().expect("Command read must not fail");
    assert_eq!(command1, test_command1);

    let command2 = read_codec.read_loco_command().expect("Command read must not fail");
    assert_eq!(command2, test_command2);
}
