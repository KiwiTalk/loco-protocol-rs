
/*
 * Created on Sun Nov 29 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::cmp::min;
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

enum State<T, U> {
	Ready(T),
	Pending(Pin<Box<dyn Future<Output=(T, Result<U, Error>)> + Send + Sync>>),
	Empty
}

pub struct SecureStreamRead<S> {
	inner: State<blocking::SecureStreamRead<S>, ()>,
}

impl<S: AsyncRead + Unpin> SecureStreamRead<S> {
	pub fn new(crypto: CryptoStore, stream: S) -> Self {
		Self {
			inner: State::Ready(blocking::SecureStreamRead::new(crypto, stream)),
		}
	}
}


impl<S: AsyncRead + Unpin> blocking::SecureStreamRead<S> {
	/// Read one encrypted packet async
	async fn read_data_async(&mut self) -> Result<(), Error> {
		let mut data_size = [0; 4];
		self.inner.read_exact(&mut data_size).await?;
		let data_size = (&data_size as &[u8]).read_u32::<LittleEndian>()? as usize;
		let mut data = vec![0; data_size];
		self.inner.read_exact(&mut data).await?;
		self.read_buf = Cursor::new(self.crypto.decrypt_aes(&data[SECURE_HEADER_SIZE..], &data[..SECURE_HEADER_SIZE])?);
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
			inner: State::Ready(blocking::SecureStreamRead {
				crypto: CryptoStore::new_with_key(
					aes_key.try_into()
						.map_err(|_| Error::InvalidKey)?,
				),
				inner: stream,
				read_buf: Default::default(),
			}),
		})
	}
}

impl<S: 'static + AsyncRead + Unpin + Send + Sync> AsyncRead for SecureStreamRead<S> {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context,
		buf: &mut [u8],
	) -> Poll<io::Result<usize>> {
		let mut future = match std::mem::replace(&mut self.inner, State::Empty) {
			State::Ready(mut inner) => {
				if !inner.read_buf.is_empty() {
					let poll = Poll::Ready(std::io::Read::read(&mut inner.read_buf, buf));
					self.inner = State::Ready(inner);
					return poll;
				}
				Box::pin(async move { let result = try {
					while inner.read_buf.is_empty() {
						inner.read_data_async().await?
					}
				}; (inner, result)})
			},
			State::Pending(future) => future,
			_ => panic!()
		};
		let poll = future.poll_unpin(cx);
		match poll {
			Poll::Ready((inner, result)) => {
				self.inner = State::Ready(inner);
				if let Err(e) = result.map_err(io_error_map) {
					Poll::Ready(Err(e))
				} else {
					self.poll_read(cx, buf)
				}
			},
			Poll::Pending => {
				self.inner = State::Pending(future);
				Poll::Pending
			}
		}
	}
}

pub struct SecureStreamWrite<S> {
	inner: State<blocking::SecureStreamWrite<S>, usize>,
}

impl<S: AsyncWrite + Unpin> SecureStreamWrite<S> {
	pub fn new(crypto: CryptoStore, stream: S) -> Self {
		Self {
			inner: State::Ready(blocking::SecureStreamWrite::new(crypto, stream))
		}
	}

	pub async fn new_handshake(crypto: CryptoStore, stream: S, pubkey: &RsaPublicKey) -> Result<Self, Error> {
		Ok(Self {
			inner: State::Ready(blocking::SecureStreamWrite::new_handshake(crypto, stream, pubkey).await?)
		})
	}
}

impl<S: AsyncWrite + Unpin> blocking::SecureStreamWrite<S> {
	pub async fn new_handshake(crypto: CryptoStore, stream: S, pubkey: &RsaPublicKey) -> Result<Self, Error> {
		let mut s = blocking::SecureStreamWrite::new(crypto, stream);
		s.write_handshake_async(pubkey).await?;
		Ok(s)
	}

	pub async fn write_handshake_async(&mut self, key: &RsaPublicKey) -> Result<(), Error> {
		let handshake = to_handshake_packet(&mut self.crypto, key)?;
		self.inner.write_all(&handshake).await?;
		self.inner.flush().await?;
		Ok(())
	}
}



impl<S: 'static + AsyncWrite + Unpin + Send + Sync> AsyncWrite for SecureStreamWrite<S> {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		let len = min(buf.len(), 2 << 16);
		let buf = &buf[..len];
		let mut future = match std::mem::replace(&mut self.inner, State::Empty) {
			State::Ready(mut inner) => {
				let mut iv = [0_u8; SECURE_HEADER_SIZE];
				inner.crypto.gen_random(&mut iv);
				let encrypted = inner.crypto.encrypt_aes(buf, &iv).unwrap();
				Box::pin(async move { let result = try {
					let mut data_size = [0u8; size_of::<u32>()];
					(&mut data_size as &mut [u8]).write_u32::<LittleEndian>((encrypted.len() + SECURE_HEADER_SIZE) as u32)?;
					inner.inner.write_all(&data_size).await?;
					inner.inner.write_all(&iv).await?;
					inner.inner.write_all(&encrypted).await?;
					encrypted.len()
				}; (inner, result)})
			},
			State::Pending(future) => future,
			_ => panic!()
		};
		let poll = future.poll_unpin(cx);
		match poll {
			Poll::Ready((inner, result)) => {
				self.inner = State::Ready(inner);
				Poll::Ready(result.map_err(io_error_map))
			},
			Poll::Pending => {
				self.inner = State::Pending(future);
				Poll::Pending
			}
		}
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
		match &mut self.inner {
			State::Ready(inner) => Pin::new(&mut inner.inner).poll_flush(cx),
			State::Pending(_) => Poll::Pending,
			State::Empty => panic!()
		}
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
		match &mut self.inner {
			State::Ready(inner) => Pin::new(&mut inner.inner).poll_close(cx),
			State::Pending(_) => Poll::Pending,
			State::Empty => panic!()
		}
	}
}

pub(super) fn io_error_map(err: Error) -> io::Error {
	match err {
		Error::Io(err) => err,

		_ => io::Error::new(io::ErrorKind::InvalidData, "Invalid encryption data"),
	}
}
