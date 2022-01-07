
/*
 * Created on Sun Nov 29 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::future::Future;
use std::pin::Pin;
use crate::secure::{blocking, SECURE_HANDSHAKE_HEAD_SIZE, SECURE_HEADER_SIZE};
use std::io;
use std::io::Cursor;
use std::mem::size_of;
use std::task::{Context, Poll};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt};
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
use crate::{CryptoError, Error};
use crate::secure::crypto::{CryptoStore, decode_handshake_head, to_handshake_packet};


pub struct SecureStreamRead<S> {
	inner: blocking::SecureStreamRead<S>,
	future: Option<Pin<Box<dyn Future<Output=Result<usize, Error>>>>>
}

impl<S: AsyncRead + Unpin> SecureStreamRead<S> {
	pub fn new(crypto: CryptoStore, stream: S) -> Self {
		Self {
			inner: blocking::SecureStreamRead::new(crypto, stream),
			future: None
		}
	}
}


impl<S: AsyncRead + Unpin> blocking::SecureStreamRead<S> {
	/// Read one encrypted packet async
	async fn read_data_async(&mut self) -> Result<(), Error> {
		println!("jjllkl");
		let mut data_size = [0; 4];
		self.inner.read_exact(&mut data_size).await?;
		let data_size = (&data_size as &[u8]).read_u32::<LittleEndian>()? as usize;
		println!("data size: {}", data_size);
		let mut data = vec![0; data_size];
		self.inner.read_exact(&mut data).await?;
		println!("read");
		self.read_buf = Cursor::new(self.crypto.decrypt_aes(&data[SECURE_HEADER_SIZE..], &data[..SECURE_HEADER_SIZE])?);
		println!("readddd: {:?}", self.read_buf);
		Ok(())
	}
}

impl<S: AsyncRead + Unpin> SecureStreamRead<S> {
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
			inner: blocking::SecureStreamRead {
				crypto: CryptoStore::new_with_key(
					aes_key.try_into()
						.map_err(|_| Error::InvalidKey)?,
				),
				inner: stream,
				read_buf: Default::default(),
			},
			future: None
		})
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for SecureStreamRead<S> {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context,
		buf: &mut [u8],
	) -> Poll<io::Result<usize>> {
		let mut future = match std::mem::replace(&mut self.future, None) {
			None => {
				Box::pin(async {
					while self.inner.read_buf.is_empty() {
						self.inner.read_data_async().await?
					}
					Ok(tokio::io::AsyncReadExt::read(&mut self.inner.read_buf, buf).await? as usize)
				})
			}
			Some(future) => future
		};
		let poll = future.poll_unpin(cx);
		if poll.is_pending() {
			self.future = unsafe {
				Some(std::mem::transmute(future as Pin<Box<dyn Future<Output=Result<usize, Error>>>>))
			};
		}
		poll.map_err(io_error_map)
	}
}

pub struct SecureStreamWrite<S> {
	inner: blocking::SecureStreamWrite<S>,
	future: Option<Pin<Box<dyn Future<Output=Result<usize, Error>>>>>
}

impl<S: AsyncWrite + Unpin> SecureStreamWrite<S> {
	pub fn new(crypto: CryptoStore, stream: S) -> Self {
		Self {
			inner: blocking::SecureStreamWrite::new(crypto, stream),
			future: None
		}
	}

	pub async fn new_handshake(crypto: CryptoStore, stream: S, pubkey: &RsaPublicKey) -> Result<Self, Error> {
		Ok(Self {
			inner: blocking::SecureStreamWrite::new_handshake(crypto, stream, pubkey).await?,
			future: None
		})
	}
}

impl<S: AsyncWrite + Unpin> blocking::SecureStreamWrite<S> {
	pub async fn new_handshake(crypto: CryptoStore, stream: S, pubkey: &RsaPublicKey) -> Result<Self, Error> {
		let mut s = blocking::SecureStreamWrite::new(crypto, stream);
		s.write_handshake_async(pubkey).await?;
		Ok(s)
	}
	/// Write data async.
	/// Returns size of packet written
	async fn write_data_async(&mut self, buf: &[u8]) -> Result<usize, Error> {
		let mut data_size = [0u8; size_of::<u32>()];
		(&mut data_size as &mut [u8]).write_u32::<LittleEndian>((buf.len() + SECURE_HEADER_SIZE) as u32)?;
		self.inner.write_all(&data_size).await?;
		let mut iv = [0_u8; SECURE_HEADER_SIZE];
		self.crypto.gen_random(&mut iv);
		self.inner.write_all(&iv).await?;
		self.inner.write_all(&self.crypto.encrypt_aes(buf, &iv)?).await?;
		Ok(buf.len())
	}

	pub async fn write_handshake_async(&mut self, key: &RsaPublicKey) -> Result<(), Error> {
		let handshake = to_handshake_packet(&mut self.crypto, key)?;
		self.inner.write_all(&handshake).await?;
		self.inner.flush().await?;
		Ok(())
	}
}



impl<S: AsyncWrite + Unpin> AsyncWrite for SecureStreamWrite<S> {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		let mut future = match std::mem::replace(&mut self.future, None) {
			None => Box::pin(self.inner.write_data_async(buf)),
			Some(future) => future
		};
		let poll = future.poll_unpin(cx);
		if poll.is_pending() {
			self.future = unsafe {
				Some(std::mem::transmute(future as Pin<Box<dyn Future<Output=Result<usize, Error>>>>))
			};
		}
		poll.map_err(io_error_map)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
		Pin::new(&mut self.inner.inner).poll_flush(cx)
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
		Pin::new(&mut self.inner.inner).poll_close(cx)
	}
}

pub(super) fn io_error_map(err: Error) -> io::Error {
	match err {
		Error::Io(err) => err,

		_ => io::Error::new(io::ErrorKind::InvalidData, "Invalid encryption data"),
	}
}
