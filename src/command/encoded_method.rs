use std::io::Write;
use std::str::FromStr;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct EncodedMethod(pub [u8; 11]);

impl FromStr for EncodedMethod {
	type Err = std::io::Error;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut method = Self([0; 11]);
		(&mut method.0 as &mut [u8]).write_all(s.as_bytes())?;
		Ok(method)
	}
}

impl TryInto<String> for EncodedMethod {
	type Error = std::string::FromUtf8Error;
	fn try_into(self) -> Result<String, Self::Error> {
		String::from_utf8(self.0.to_vec())
	}
}