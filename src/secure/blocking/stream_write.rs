use std::io;
use std::io::Write;
use byteorder::{LittleEndian, WriteBytesExt};
use rsa::RsaPublicKey;
use crate::Error;
use crate::secure::crypto::{CryptoStore, to_handshake_packet};
use crate::secure::SECURE_HEADER_SIZE;
use crate::secure::secure_stream::io_error_map;

#[derive(Debug)]
pub struct SecureStreamWrite<S> {
	pub(in crate::secure) crypto: CryptoStore,
	pub(in crate::secure) inner: S,
}

impl<S> SecureStreamWrite<S> {
	pub fn new(crypto: CryptoStore, stream: S) -> Self {
		Self {
			crypto,
			inner: stream,
		}
	}

	pub fn crypto(&self) -> &CryptoStore {
		&self.crypto
	}

	pub fn into_inner(self) -> S {
		self.inner
	}
}

impl<S: Write> SecureStreamWrite<S> {
	/// Write data.
	/// Returns size of packet written
	fn write_data(&mut self, buf: &[u8]) -> Result<(), Error> {
		self.inner.write_u32::<LittleEndian>((buf.len() + SECURE_HEADER_SIZE) as u32)?;
		let mut iv = [0_u8; SECURE_HEADER_SIZE];
		self.crypto.gen_random(&mut iv);
		self.inner.write_all(&iv)?;
		self.inner.write_all(&self.crypto.encrypt_aes(buf, &iv)?)?;
		Ok(())
	}

	pub fn write_handshake(&mut self, key: &RsaPublicKey) -> Result<(), Error> {
		let handshake = to_handshake_packet(&mut self.crypto, key)?;
		self.inner.write_all(&handshake)?;
		Ok(())
	}
}


impl<S: Write> Write for SecureStreamWrite<S> {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.write_data(buf).map_err(io_error_map)?;
		Ok(buf.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		self.inner.flush()
	}
}