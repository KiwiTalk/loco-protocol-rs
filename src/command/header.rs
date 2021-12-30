use crate::command::EncodedMethod;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct LocoHeader {
	pub id: i32,
	pub status: i16,
	pub method: EncodedMethod,
	pub data_type: i8,
}