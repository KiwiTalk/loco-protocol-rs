#![feature(buf_read_has_data_left, trait_alias, cursor_remaining, try_blocks)]
/*
 * Created on Sat Nov 28 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

#![doc = include_str!("../specification.md")]

pub mod secure;

mod loco_header;
mod loco_instance;
mod encoded_method;

pub use loco_header::*;
pub use loco_instance::*;
pub use encoded_method::*;

use std::io;
use std::string::FromUtf8Error;
use crate::secure::crypto::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
	#[error("{0}")]
	Bincode(#[from] bincode::Error),
	#[error("{0}")]
	Io(#[from] io::Error),
	#[error("{0}")]
	Crypto(#[from] CryptoError),
	#[error("{0}")]
	BsonDe(#[from] bson::de::Error),
	#[error("{0}")]
	BsonSer(#[from] bson::ser::Error),
	#[error("Invalid Key")]
	InvalidKey,
	#[error("failed to send channel")]
	TokioSendFail,
	#[error("{0}")]
	TokioRecvFail(#[from] tokio::sync::oneshot::error::RecvError),
	#[error("packet receive timed out")]
	LocoTimeout,
	#[error("error while deserializing EncodedMethod: {0}")]
	EncodedMethodDeserializeError(#[from] FromUtf8Error)
}


/*
#[derive(Clone, Debug)]
pub struct ArcError{
	pub inner: Arc<Error>
}

impl<T: Into<Error>> From<T> for ArcError {
	fn from(e: T) -> Self {
		Self {
			inner: Arc::new(e.into())
		}
	}
}

impl Display for ArcError {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		Display::fmt(&*self.inner, f)
	}
}

impl std::error::Error for ArcError {
}
*/