/*
 * Created on Sat Nov 28 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub mod builder;

mod encoded_method;
mod header;

pub use encoded_method::*;
pub use header::*;

use std::io::{Read, Write};
use std::mem::size_of;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Error;


pub const HEADER_SIZE: usize = 18;
pub const HEAD_SIZE: usize = HEADER_SIZE + 4;


/// Loco protocol Command packet
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LocoCommand {
    pub header: LocoHeader,
    pub data: Vec<u8>,
}

impl LocoCommand {
    pub fn serialize_into<W: Write>(&self, mut w: W) -> Result<(), Error> {
        bincode::serialize_into(&mut w, &self.header)?;
        w.write_u32::<LittleEndian>(self.data.len() as u32)?;
        Ok(w.write_all(&self.data)?)
    }

    pub async fn async_serialize_into<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<(), Error> {
        let mut header_and_size = [0u8; HEADER_SIZE];
        let mut header_and_size_writer = &mut header_and_size as &mut [u8];
        bincode::serialize_into(&mut header_and_size_writer, &self.header)?;
        header_and_size_writer.write_u32::<LittleEndian>(self.data.len() as u32)?;
        w.write_all(&header_and_size).await?;
        Ok(w.write_all(&self.data).await?)
    }

    pub fn deserialize_from<R: Read>(mut r: R) -> Result<Self, Error> {
        let header: LocoHeader = bincode::deserialize_from(&mut r)?;
        let data_size = r.read_u32::<LittleEndian>()? as usize;
        let mut data = vec![0; data_size];
        r.read_exact(&mut data)?;
        Ok(Self {
            header,
            data
        })
    }

    pub async fn async_deserialize_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, Error> {
        let mut header_and_size = [0; HEADER_SIZE + size_of::<u32>()];
        r.read_exact(&mut header_and_size).await?;
        let mut header_and_size_reader = &header_and_size as &[u8];
        let header = bincode::deserialize_from(&mut header_and_size_reader)?;
        let data_size = header_and_size_reader.read_u32::<LittleEndian>()? as usize;
        let mut data = vec![0; data_size];
        r.read_exact(&mut data).await?;
        Ok(Self {
            header,
            data
        })
    }
}

pub trait WriteLocoCommand {
    fn write_loco_command(&mut self, command: &LocoCommand) -> Result<(), Error>;
}

impl<T: Write> WriteLocoCommand for T {
    fn write_loco_command(&mut self, command: &LocoCommand) -> Result<(), Error> {
        Ok(command.serialize_into(self)?)
    }
}

#[async_trait::async_trait]
pub trait AsyncWriteLocoCommand {
    async fn async_write_loco_command(&mut self, command: &LocoCommand) -> Result<(), Error>;
}

#[async_trait::async_trait]
impl<T: AsyncWrite + Unpin + Send> AsyncWriteLocoCommand for T {
    async fn async_write_loco_command(&mut self, command: &LocoCommand) -> Result<(), Error> {
        command.async_serialize_into(self).await
    }
}

pub trait ReadLocoCommand {
    fn read_loco_command(&mut self) -> Result<LocoCommand, Error>;
}

impl<T: Read> ReadLocoCommand for T {
    fn read_loco_command(&mut self) -> Result<LocoCommand, Error> {
        LocoCommand::deserialize_from(self)
    }
}

#[async_trait::async_trait]
pub trait AsyncReadLocoCommand {
    async fn async_read_loco_command(&mut self) -> Result<LocoCommand, Error>;
}

#[async_trait::async_trait]
impl<T: AsyncRead + Unpin + Send> AsyncReadLocoCommand for T {
    async fn async_read_loco_command(&mut self) -> Result<LocoCommand, Error> {
        LocoCommand::async_deserialize_from(self).await
    }
}
