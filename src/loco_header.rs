use serde::{Serialize, Deserialize};
use serde_repr::{Serialize_repr, Deserialize_repr};
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


#[derive(Serialize_repr, Deserialize_repr, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(i8)]
pub enum BodyType {
	Bson = 0
}