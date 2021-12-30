
/*
 * Created on Sun Nov 29 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::{
	io::{self, Read, Write},
	pin::Pin,
	task::{Context, Poll},
};
use std::mem::size_of;
use std::io::{BufRead, Cursor};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use futures::{ready, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt};
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};

use crate::{CryptoError, Error};
use crate::secure::crypto::{decode_handshake_head, to_handshake_packet};
use crate::secure::{SECURE_HANDSHAKE_HEAD_SIZE, SECURE_HEADER_SIZE};

use super::crypto::CryptoStore;


/// Secure layer used in client and server
#[derive(Debug)]
pub struct SecureStream<S> {
	crypto: CryptoStore,
	inner: S,
	read_buf: Cursor<Vec<u8>>
}

impl<S> SecureStream<S> {
	pub fn new(crypto: CryptoStore, stream: S) -> Self {
		Self {
			crypto,
			inner: stream,
			read_buf: Default::default(),
		}
	}

	pub fn crypto(&self) -> &CryptoStore {
		&self.crypto
	}

	pub fn into_inner(self) -> S {
		self.inner
	}
}

impl<S: Read> SecureStream<S> {
	/// Read one encrypted packet
	fn read_data(&mut self) -> Result<(), Error> {
		let data_size = self.inner.read_u32::<LittleEndian>()? as usize;
		let mut iv = [0; SECURE_HEADER_SIZE];
		self.inner.read_exact(&mut iv)?;
		let mut data = Vec::with_capacity(data_size);
		self.inner.read_exact(&mut data)?;
		self.read_buf = Cursor::new(self.crypto.decrypt_aes(&data, &iv)?);
		Ok(())
	}

	pub fn read_handshake(mut stream: S, key: &RsaPrivateKey) -> Result<Self, Error> {
		let mut handshake_head_buf = [0_u8; SECURE_HANDSHAKE_HEAD_SIZE];
		stream.read_exact(&mut handshake_head_buf)?;

		let mut handshake = decode_handshake_head(&handshake_head_buf)?;
		stream.read_exact(&mut handshake.encrypted_key)?;

		let aes_key = key
			.decrypt(
				PaddingScheme::new_oaep::<sha1::Sha1>(),
				&handshake.encrypted_key,
			)
			.map_err(|_| CryptoError::CorruptedData)?;

		Ok(Self {
			crypto: CryptoStore::new_with_key(
				aes_key.try_into()
					.map_err(|_| Error::InvalidKey)?,
			),
			inner: stream,
			read_buf: Default::default()
		})
	}
}

impl<S: Write> SecureStream<S> {
	/// Write data.
	/// Returns size of packet written
	fn write_data(&mut self, buf: &[u8]) -> Result<(), Error> {
		self.inner.write_u32::<LittleEndian>(buf.len() as u32)?;
		let mut iv = [0_u8; SECURE_HEADER_SIZE];
		self.crypto.gen_random(&mut iv);
		self.inner.write_all(&iv)?;
		self.inner.write_all(&self.crypto.encrypt_aes(buf, &iv)?)?;
		Ok(())
	}

	pub fn write_handshake(&mut self, key: &RsaPublicKey) -> Result<(), Error> {
		let handshake = to_handshake_packet(&self.crypto, key)?;
		Ok(self.write_all(&handshake)?)
	}
}

impl<S: Read> Read for SecureStream<S> {
	fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
		while !self.read_buf.has_data_left()? {
			self.read_data().map_err(io_error_map)?
		}

		io::copy(&mut self.read_buf, &mut buf).map(|x| x as usize)
	}
}

impl<S: Write> Write for SecureStream<S> {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.write_data(buf).map_err(io_error_map)?;
		Ok(buf.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		self.inner.flush()
	}
}

impl<S: AsyncRead + Unpin> SecureStream<S> {
	/// Read one encrypted packet async
	async fn read_data_async(&mut self) -> Result<(), Error> {
		let mut data_size = [0; size_of::<u32>()];
		self.inner.read_exact(&mut data_size).await?;
		let data_size = (&data_size as &[u8]).read_u32::<LittleEndian>()? as usize;
		let mut iv = [0; SECURE_HEADER_SIZE];
		self.inner.read_exact(&mut iv).await?;
		let mut read = Vec::with_capacity(data_size);
		self.inner.read_exact(&mut read).await?;
		self.read_buf = Cursor::new(self.crypto.decrypt_aes(&read, &iv)?);
		Ok(())
	}

	pub async fn read_handshake_async(mut stream: S, key: &RsaPrivateKey) -> Result<Self, Error> {
		let mut handshake_head_buf = [0_u8; SECURE_HANDSHAKE_HEAD_SIZE];
		stream.read_exact(&mut handshake_head_buf).await?;

		let mut handshake = decode_handshake_head(&handshake_head_buf)?;
		stream.read_exact(&mut handshake.encrypted_key).await?;

		let aes_key = key
			.decrypt(
				PaddingScheme::new_oaep::<sha1::Sha1>(),
				&handshake.encrypted_key,
			)
			.map_err(|_| CryptoError::CorruptedData)?;

		Ok(Self {
			crypto: CryptoStore::new_with_key(
				aes_key.try_into()
					.map_err(|_| Error::InvalidKey)?,
			),
			inner: stream,
			read_buf: Default::default()
		})
	}
}

impl<S: AsyncWrite + Unpin> SecureStream<S> {
	/// Write data async.
	/// Returns size of packet written
	async fn write_data_async(&mut self, buf: &[u8]) -> Result<(), Error> {
		let mut data_size = [0u8; size_of::<u32>()];
		(&mut data_size as &mut [u8]).write_u32::<LittleEndian>(buf.len() as u32)?;
		self.inner.write_all(&data_size).await?;
		let mut iv = [0_u8; SECURE_HEADER_SIZE];
		self.crypto.gen_random(&mut iv);
		self.inner.write_all(&iv).await?;
		self.inner.write_all(&self.crypto.encrypt_aes(buf, &iv)?).await?;
		Ok(())
	}

	pub async fn write_handshake_async(&mut self, key: &RsaPublicKey) -> Result<(), Error> {
		let handshake = to_handshake_packet(&self.crypto, key)?;
		Ok(self.inner.write_all(&handshake).await?)
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for SecureStream<S> {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context,
		buf: &mut [u8],
	) -> Poll<io::Result<usize>> {
		let read = ready!(
			Box::pin(async {
				while !self.read_buf.has_data_left()? {
					self.read_data_async().await.map_err(io_error_map)?
				}
				Ok(tokio::io::copy(&mut self.read_buf, &mut Cursor::new(buf)).await?)
			}).poll_unpin(cx).map_err(io_error_map)
		)?;
		Poll::Ready(Ok(read as usize))
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SecureStream<S> {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		ready!(Box::pin(self.write_data_async(&buf))
            .poll_unpin(cx)
            .map_err(io_error_map))?;

		Poll::Ready(Ok(buf.len()))
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
		Pin::new(&mut self.inner).poll_flush(cx)
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
		Pin::new(&mut self.inner).poll_close(cx)
	}
}

fn io_error_map(err: Error) -> io::Error {
	match err {
		Error::Io(err) => err,

		_ => io::Error::new(io::ErrorKind::InvalidData, "Invalid encryption data"),
	}
}
