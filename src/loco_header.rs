use serde::{Serialize, Deserialize};
use crate::EncodedMethod;

pub const HEADER_SIZE: usize = 22;

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct LocoHeader {
	pub id: i32,
	pub status: i16,
	pub method: EncodedMethod,
	pub body_type: BodyType,
	pub body_size: u32
}

#[repr(i8)]
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum BodyType {
	Bson = 0,
	#[serde(other)]
	Unknown = -1,
}