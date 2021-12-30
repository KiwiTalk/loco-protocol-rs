#![feature(buf_read_has_data_left)]
/*
 * Created on Sat Nov 28 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

#![doc = include_str!("../specification.md")]

pub mod command;

pub mod secure;

use std::fmt::Display;
use std::io;
use crate::secure::crypto::CryptoError;

#[derive(Debug)]
pub enum Error {
	Bincode(bincode::Error),
	Io(io::Error),
	Crypto(CryptoError),
	InvalidKey,
}

impl From<bincode::Error> for Error {
	fn from(err: bincode::Error) -> Self {
		Self::Bincode(err)
	}
}

impl From<io::Error> for Error {
	fn from(err: io::Error) -> Self {
		Self::Io(err)
	}
}

impl From<CryptoError> for Error {
	fn from(err: CryptoError) -> Self {
		Self::Crypto(err)
	}
}

impl Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Error::Bincode(err) => err.fmt(f),
			Error::Io(err) => err.fmt(f),
			Error::Crypto(err) => err.fmt(f),
			Error::InvalidKey => write!(f, "Invalid key"),
		}
	}
}