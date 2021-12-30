/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use loco_protocol::command::{builder::CommandBuilder, LocoCommand, LocoHeader};

#[test]
pub fn command_builder() {
    let builder = CommandBuilder::new(0, &"TEST");

    let test_command = LocoCommand {
        header: LocoHeader {
            id: 0,
            data_type: 0,
            status: 0,
            method: "TEST".into()
        },
        data: vec![0_u8; 4],
    };

    let command = builder.build(0, vec![0_u8; 4]);

    assert_eq!(test_command, command)
}
