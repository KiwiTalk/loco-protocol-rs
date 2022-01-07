use std::io;
use std::io::{BufRead, Cursor, Read};
use byteorder::{LittleEndian, ReadBytesExt};
use rsa::{PaddingScheme, RsaPrivateKey};
use crate::{CryptoError, Error};
use crate::secure::crypto::{CryptoStore, decode_handshake_head};
use crate::secure::{SECURE_HANDSHAKE_HEAD_SIZE, SECURE_HEADER_SIZE};
use crate::secure::secure_stream::io_error_map;

/// Secure layer used in client and server
#[derive(Debug)]
pub struct SecureStreamRead<S> {
	pub(in crate::secure) crypto: CryptoStore,
	pub(in crate::secure) inner: S,
	pub(in crate::secure) read_buf: Cursor<Vec<u8>>,
}

impl<S> SecureStreamRead<S> {
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

impl<S: Read> SecureStreamRead<S> {
	/// Read one encrypted packet
	fn read_data(&mut self) -> Result<(), Error> {
		let data_size = self.inner.read_u32::<LittleEndian>()? as usize;
		let mut data = vec![0; data_size];
		self.inner.read_exact(&mut data)?;
		self.read_buf = Cursor::new(self.crypto.decrypt_aes(&data[SECURE_HEADER_SIZE..], &data[..SECURE_HEADER_SIZE])?);
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
			read_buf: Default::default(),
		})
	}
}

impl<S: Read> Read for SecureStreamRead<S> {
	fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
		while !self.read_buf.has_data_left()? {
			self.read_data().map_err(io_error_map)?
		}

		io::copy(&mut self.read_buf, &mut buf).map(|x| x as usize)
	}
}