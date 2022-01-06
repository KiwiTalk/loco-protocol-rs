use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use bson::Document;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::lock::Mutex;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::{oneshot, broadcast};
use std::time::Instant;
use crate::{BodyType, EncodedMethod, Error, HEADER_SIZE, LocoHeader};
use log::{error, warn, debug, info, trace};

const TIMEOUT: Duration = Duration::from_secs(20);

struct LocoInstanceMutex<T> {
	write: T,
	last_packet_id: i32,
	oneshot: HashMap<i32, (Instant, EncodedMethod, oneshot::Sender<Result<Document, Error>>)>,
}

struct LocoInstanceArc<R, W> {
	mutex: Mutex<LocoInstanceMutex<W>>,
	read: Mutex<R>,
	broadcast_bson: broadcast::Sender<Arc<Result<(String, Document), Error>>>,
	stop: Mutex<bool>
}

pub struct LocoInstance<R, W> {
	arc: Arc<LocoInstanceArc<R, W>>,
}

impl<R, W> Clone for LocoInstance<R, W> {
	fn clone(&self) -> Self {
		Self {
			arc: self.arc.clone()
		}
	}
}

pub trait LocoInstanceRead = AsyncRead + Unpin + Sync + Send + 'static;
pub trait LocoInstanceWrite = AsyncWrite + Unpin + Sync + Send + 'static;

impl<R: LocoInstanceRead, W: LocoInstanceWrite> LocoInstance<R, W> {
	pub fn init(read: R, write: W) -> Self {
		let instance = Self {
			arc: Arc::new(LocoInstanceArc {
				mutex: Mutex::new(LocoInstanceMutex {
					write,
					last_packet_id: 0,
					oneshot: HashMap::default(),
				}),
				read: Mutex::new(read),
				broadcast_bson: broadcast::channel(100).0,
				stop: Mutex::new(false)
			})
		};
		instance
	}

	pub async fn run(&self) {
		info!("LocoInstance started");
		let mut to_remove = vec![];
		while !*self.arc.stop.lock().await {
			let result: Result<_, Error> = async {
				let mut read = self.arc.read.lock().await;
				let mut header_reader = [0; HEADER_SIZE];
				println!("!");
				read.read_exact(&mut header_reader).await?;
				println!("!");
				let loco_header: LocoHeader = bincode::deserialize_from(&header_reader as &[u8])?;
				trace!("packet id: {}, method: {}", loco_header.id, TryInto::<String>::try_into(loco_header.method)?);
				let mut body_raw = vec![0; loco_header.body_size as usize];
				read.read_exact(&mut body_raw).await?;
				let mut mutex = self.arc.mutex.lock().await;
				if (loco_header.id as u32) >= (mutex.last_packet_id as u32) {
					mutex.last_packet_id = loco_header.id;
				}
				match loco_header.body_type {
					BodyType::Bson => {
						let result: Result<Document, Error> = {
							Ok(bson::Document::from_reader(&*body_raw)?)
						};
						if let Some((_, method, sender)) = mutex.oneshot.remove(&loco_header.id) {
							let method_expected: String = method.try_into()?;
							let method_found: String = loco_header.method.try_into()?;
							if method_expected != method_found {
								warn!("method expected: {}, found: {}", method_expected, method_found);
							}
							sender.send(result).map_err(|_| Error::TokioSendFail)?;
						} else {
							let method: String = loco_header.method.try_into()?;
							self.arc.broadcast_bson.send(Arc::new(result.map(|x| (method, x)))).map_err(|_| Error::TokioSendFail)?;
						}
					}
					BodyType::Unknown => {}
				}


				let now = Instant::now();
				to_remove.clear();
				for (key, (sent_time, _, _)) in mutex.oneshot.iter() {
					if now.duration_since(sent_time.clone()) > TIMEOUT {
						to_remove.push(*key);
					}
				}

				for x in &to_remove {
					if let Some((_, method, sender)) = mutex.oneshot.remove(x) {
						debug!("packet id: {}, method: {}, dropped due to timeout", x, TryInto::<String>::try_into(method)?);
						sender.send(Err(Error::LocoTimeout)).map_err(|_| Error::TokioSendFail)?;
					}
				}
				Ok(())
			}.await;
			result.unwrap();
			//if let Err(e) = result {
			//	error!("error on LocoInstance loop: {:#?}", e);
			//	e.prin
			//}
		}
		info!("LocoInstance stopped");
	}

	pub async fn stop(&self) {
		info!("LocoInstance stopping...");
		*self.arc.stop.lock().await = true
	}

	pub fn subscribe_bson(&self) -> broadcast::Receiver<Arc<Result<(String, Document), Error>>> {
		self.arc.broadcast_bson.subscribe()
	}

	pub async fn send_and_receive_bson<REQ: Serialize, RES: DeserializeOwned>(&self, method: &str, request: &REQ) -> Result<RES, Error> {
		let (receiver, packet_id) = {
			let mut mutex = self.arc.mutex.lock().await;
			mutex.last_packet_id += 1;
			let (sender, receiver) = oneshot::channel();
			let id = mutex.last_packet_id;
			mutex.oneshot.insert(id, (Instant::now(), method.parse()?, sender));
			(receiver, mutex.last_packet_id)
		};
		self.send_bson_with_pid(method, packet_id, request).await?;
		Ok(bson::from_document(receiver.await??)?)
	}

	pub async fn send_bson<REQ: Serialize>(&self, method: &str, request: &REQ) -> Result<(), Error> {
		let packet_id = {
			let mut mutex = self.arc.mutex.lock().await;
			mutex.last_packet_id += 1;
			mutex.last_packet_id
		};
		self.send_bson_with_pid(method, packet_id, request).await
	}

	async fn send_bson_with_pid<REQ: Serialize>(&self, method: &str, packet_id: i32, request: &REQ) -> Result<(), Error> {
		let mut mutex = self.arc.mutex.lock().await;
		let body_raw = bson::to_vec(&request)?;
		let header = LocoHeader {
			id: packet_id,
			status: 0,
			method: method.parse()?,
			body_type: BodyType::Bson,
			body_size: body_raw.len() as _
		};
		mutex.write.write_all(&bincode::serialize(&header)?).await?;
		mutex.write.write_all(&body_raw).await?;
		mutex.write.flush().await?;
		Ok(())
	}
}
