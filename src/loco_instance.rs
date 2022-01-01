use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use bson::Document;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::lock::Mutex;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::{oneshot, broadcast};
use tokio::task::JoinHandle;
use std::time::Instant;
use crate::{ArcError, BodyType, Error, HEADER_SIZE, LocoHeader};

const TIMEOUT: Duration = Duration::from_secs(1);

struct LocoInstanceMutex<T> {
	stream: T,
	last_packet_id: i32,
	oneshot: HashMap<i32, (Instant, oneshot::Sender<Result<Document, Error>>)>
}

struct LocoInstanceArc<T> {
	mutex: Mutex<LocoInstanceMutex<T>>,
	broadcast_bson: broadcast::Sender<Result<Arc<Document>, ArcError>>
}

pub struct LocoInstance<T> {
	arc: Arc<LocoInstanceArc<T>>,
}

impl<T> Clone for LocoInstance<T> {
	fn clone(&self) -> Self {
		Self {
			arc: self.arc.clone()
		}
	}
}

impl<T: AsyncRead + AsyncWrite + Unpin + Sync + Send + 'static> LocoInstance<T> {
	pub fn init(stream: T) -> (Self, JoinHandle<Result<(), Error>>) {
		let instance = Self {
			arc: Arc::new(LocoInstanceArc {
				mutex: Mutex::new(LocoInstanceMutex {
					stream,
					last_packet_id: 0,
					oneshot: HashMap::default()
				}),
				broadcast_bson: broadcast::channel(100).0
			})
		};
		let instance_clone = instance.clone();
		let handle = tokio::spawn(async move {
			instance_clone.run().await
		});
		(instance, handle)
	}

	async fn run(&self) -> Result<(), Error> {
		let mut to_remove = vec![];
		loop {
			let mut mutex = self.arc.mutex.lock().await;
			let mut header_reader = [0; HEADER_SIZE];
			mutex.stream.read_exact(&mut header_reader).await?;
			let loco_header: LocoHeader = bincode::deserialize_from(&header_reader as &[u8])?;
			if (loco_header.id as u32) >= (mutex.last_packet_id as u32) {
				mutex.last_packet_id = loco_header.id;
			}
			let mut body_raw = vec![0; loco_header.body_size as usize];
			mutex.stream.read_exact(&mut body_raw).await?;
			match loco_header.body_type {
				BodyType::Bson => {
					let result: Result<Document, Error> = {
						Ok(bson::Document::from_reader(&*body_raw)?)
					};
					if let Some((_, sender)) = mutex.oneshot.remove(&loco_header.id) {
						sender.send(result).map_err(|_| Error::TokioSendFail)?;
					} else {
						self.arc.broadcast_bson.send(result.map(Arc::new).map_err(Into::into)).map_err(|_| Error::TokioSendFail)?;
					}
				}
				BodyType::Unknown => {}
			}


			let now = Instant::now();
			to_remove.clear();
			for (key, (sent_time, _)) in mutex.oneshot.iter() {
				if now.duration_since(sent_time.clone()) > TIMEOUT {
					to_remove.push(*key);
				}
			}

			//todo timeout drop debug log
			for x in &to_remove {
				mutex.oneshot.remove(x);
			}
		}
	}

	pub fn subscribe_bson(&self) -> broadcast::Receiver<Result<Arc<Document>, ArcError>> {
		self.arc.broadcast_bson.subscribe()
	}

	pub async fn request_and_receive_bson<REQ: Serialize, RES: DeserializeOwned>(&self, method: &str, request: &REQ) -> Result<RES, ArcError> {
		let receiver = {
			let mut mutex = self.arc.mutex.lock().await;
			mutex.last_packet_id += 1;
			let (sender, receiver) = oneshot::channel();
			let id = mutex.last_packet_id;
			mutex.oneshot.insert(id, (Instant::now(), sender));
			receiver
		};
		self.request_bson(method, request).await?;
		Ok(bson::from_document(receiver.await??)?)
	}

	pub async fn request_bson<REQ: Serialize>(&self, method: &str, request: &REQ) -> Result<(), Error> {
		let mut mutex = self.arc.mutex.lock().await;
		let body_raw = bson::to_vec(&request)?;
		let header = LocoHeader {
			id: mutex.last_packet_id,
			status: 0,
			method: method.parse()?,
			body_type: BodyType::Bson,
			body_size: body_raw.len() as _
		};
		mutex.stream.write_all(&bincode::serialize(&header)?).await?;
		mutex.stream.write_all(&body_raw).await?;
		Ok(())
	}
}
