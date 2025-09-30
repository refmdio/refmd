use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use redis::AsyncCommands;
use redis::streams::{StreamRangeReply, StreamReadOptions, StreamReadReply};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_stream::wrappers::UnboundedReceiverStream;

const FIELD_FRAME: &str = "frame";
const FIELD_AWARENESS: &str = "awareness";
const FIELD_TASK_DOC: &str = "doc";

#[derive(Clone)]
pub struct RedisClusterBus {
    client: Arc<redis::Client>,
    stream_prefix: String,
    stream_max_len: Option<usize>,
    poll_interval: Duration,
}

pub type StreamItem = (String, Vec<u8>);
pub type TaskItem = (String, String);

impl RedisClusterBus {
    pub fn new(
        client: redis::Client,
        stream_prefix: impl Into<String>,
        stream_max_len: Option<usize>,
        poll_interval: Duration,
    ) -> Self {
        let stream_max_len = stream_max_len.and_then(|len| if len == 0 { None } else { Some(len) });
        Self {
            client: Arc::new(client),
            stream_prefix: stream_prefix.into(),
            stream_max_len,
            poll_interval,
        }
    }

    fn updates_key(&self, doc_id: &str) -> String {
        format!("{}:{}:updates", self.stream_prefix, doc_id)
    }

    fn awareness_key(&self, doc_id: &str) -> String {
        format!("{}:{}:awareness", self.stream_prefix, doc_id)
    }

    fn tasks_key(&self) -> String {
        format!("{}:tasks", self.stream_prefix)
    }

    pub async fn publish_update(&self, doc_id: &str, frame: Vec<u8>) -> anyhow::Result<String> {
        let mut conn = self
            .client
            .get_async_connection()
            .await
            .context("redis_get_async_connection")?;
        let key = self.updates_key(doc_id);
        let mut cmd = redis::cmd("XADD");
        cmd.arg(&key);
        if let Some(max_len) = self.stream_max_len {
            cmd.arg("MAXLEN").arg("~").arg(max_len as i64);
        }
        let id: String = cmd
            .arg("*")
            .arg(FIELD_FRAME)
            .arg(frame)
            .query_async(&mut conn)
            .await
            .context("redis_xadd_update")?;

        // Schedule a background persistence task (best effort)
        let mut task_cmd = redis::cmd("XADD");
        task_cmd.arg(self.tasks_key());
        if let Some(max_len) = self.stream_max_len {
            task_cmd.arg("MAXLEN").arg("~").arg(max_len as i64);
        }
        let _ = task_cmd
            .arg("*")
            .arg("doc")
            .arg(doc_id)
            .query_async::<_, redis::Value>(&mut conn)
            .await;
        Ok(id)
    }

    pub async fn publish_awareness(
        &self,
        doc_id: &str,
        payload: Vec<u8>,
    ) -> anyhow::Result<String> {
        let mut conn = self
            .client
            .get_async_connection()
            .await
            .context("redis_get_async_connection")?;
        let key = self.awareness_key(doc_id);
        let mut cmd = redis::cmd("XADD");
        cmd.arg(&key);
        if let Some(max_len) = self.stream_max_len {
            cmd.arg("MAXLEN").arg("~").arg(max_len as i64);
        }
        let id: String = cmd
            .arg("*")
            .arg(FIELD_AWARENESS)
            .arg(payload)
            .query_async(&mut conn)
            .await
            .context("redis_xadd_awareness")?;
        Ok(id)
    }

    pub async fn read_update_backlog(
        &self,
        doc_id: &str,
        from_id: Option<&str>,
    ) -> anyhow::Result<Vec<StreamItem>> {
        let key = self.updates_key(doc_id);
        let start = from_id
            .map(|id| format!("({id}"))
            .unwrap_or_else(|| "-".to_string());
        let mut conn = self
            .client
            .get_async_connection()
            .await
            .context("redis_get_async_connection")?;
        let reply: StreamRangeReply = conn
            .xrange(&key, start, "+")
            .await
            .context("redis_xrange_updates")?;
        Ok(reply
            .ids
            .into_iter()
            .filter_map(|entry| {
                entry
                    .get::<Vec<u8>>(FIELD_FRAME)
                    .map(|data| (entry.id, data))
            })
            .collect())
    }

    pub async fn read_awareness_backlog(
        &self,
        doc_id: &str,
        from_id: Option<&str>,
    ) -> anyhow::Result<Vec<StreamItem>> {
        let key = self.awareness_key(doc_id);
        let start = from_id
            .map(|id| format!("({id}"))
            .unwrap_or_else(|| "-".to_string());
        let mut conn = self
            .client
            .get_async_connection()
            .await
            .context("redis_get_async_connection")?;
        let reply: StreamRangeReply = conn
            .xrange(&key, start, "+")
            .await
            .context("redis_xrange_awareness")?;
        Ok(reply
            .ids
            .into_iter()
            .filter_map(|entry| {
                entry
                    .get::<Vec<u8>>(FIELD_AWARENESS)
                    .map(|data| (entry.id, data))
            })
            .collect())
    }

    pub async fn subscribe_updates(
        &self,
        doc_id: &str,
        start_id: Option<String>,
    ) -> anyhow::Result<UnboundedReceiverStream<anyhow::Result<StreamItem>>> {
        let key = self.updates_key(doc_id);
        Ok(self.spawn_stream_reader_bytes(key, FIELD_FRAME, start_id))
    }

    pub async fn subscribe_awareness(
        &self,
        doc_id: &str,
        start_id: Option<String>,
    ) -> anyhow::Result<UnboundedReceiverStream<anyhow::Result<StreamItem>>> {
        let key = self.awareness_key(doc_id);
        Ok(self.spawn_stream_reader_bytes(key, FIELD_AWARENESS, start_id))
    }

    pub async fn subscribe_tasks(
        &self,
        start_id: Option<String>,
    ) -> anyhow::Result<UnboundedReceiverStream<anyhow::Result<TaskItem>>> {
        Ok(self.spawn_stream_reader_strings(self.tasks_key(), FIELD_TASK_DOC, start_id))
    }

    pub async fn ack_task(&self, entry_id: &str) -> anyhow::Result<()> {
        let mut conn = self
            .client
            .get_async_connection()
            .await
            .context("redis_get_async_connection")?;
        let _: i64 = redis::cmd("XDEL")
            .arg(self.tasks_key())
            .arg(entry_id)
            .query_async(&mut conn)
            .await
            .context("redis_xdel_task")?;
        Ok(())
    }

    fn spawn_stream_reader_bytes(
        &self,
        key: String,
        field: &'static str,
        start_id: Option<String>,
    ) -> UnboundedReceiverStream<anyhow::Result<StreamItem>> {
        let client = self.client.clone();
        let poll_interval = self.poll_interval;
        let mut last_id = start_id.unwrap_or_else(|| "$".to_string());
        let (tx, rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            loop {
                match client.get_async_connection().await {
                    Ok(mut conn) => {
                        let opts = StreamReadOptions::default().block(1000).count(128);
                        let keys = [key.as_str()];
                        let ids = [last_id.as_str()];
                        let reply: redis::RedisResult<StreamReadReply> =
                            conn.xread_options(&keys, &ids, &opts).await;
                        match reply {
                            Ok(data) => {
                                let mut advanced = false;
                                for stream_key in data.keys {
                                    for entry in stream_key.ids {
                                        if let Some(value) = entry.get::<Vec<u8>>(field) {
                                            last_id = entry.id.clone();
                                            advanced = true;
                                            if tx.send(Ok((entry.id, value))).is_err() {
                                                return;
                                            }
                                        }
                                    }
                                }
                                if !advanced {
                                    tokio::task::yield_now().await;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(stream = %key, error = ?e, "redis_stream_read_failed");
                                sleep(poll_interval).await;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(stream = %key, error = ?e, "redis_stream_connect_failed");
                        sleep(poll_interval).await;
                    }
                }
            }
        });

        UnboundedReceiverStream::new(rx)
    }

    fn spawn_stream_reader_strings(
        &self,
        key: String,
        field: &'static str,
        start_id: Option<String>,
    ) -> UnboundedReceiverStream<anyhow::Result<TaskItem>> {
        let client = self.client.clone();
        let poll_interval = self.poll_interval;
        let mut last_id = start_id.unwrap_or_else(|| "$".to_string());
        let (tx, rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            loop {
                match client.get_async_connection().await {
                    Ok(mut conn) => {
                        let opts = StreamReadOptions::default().block(1000).count(128);
                        let keys = [key.as_str()];
                        let ids = [last_id.as_str()];
                        let reply: redis::RedisResult<StreamReadReply> =
                            conn.xread_options(&keys, &ids, &opts).await;
                        match reply {
                            Ok(data) => {
                                let mut advanced = false;
                                for stream_key in data.keys {
                                    for entry in stream_key.ids {
                                        if let Some(value) = entry.get::<String>(field) {
                                            last_id = entry.id.clone();
                                            advanced = true;
                                            if tx.send(Ok((entry.id, value))).is_err() {
                                                return;
                                            }
                                        }
                                    }
                                }
                                if !advanced {
                                    tokio::task::yield_now().await;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(stream = %key, error = ?e, "redis_stream_read_failed");
                                sleep(poll_interval).await;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(stream = %key, error = ?e, "redis_stream_connect_failed");
                        sleep(poll_interval).await;
                    }
                }
            }
        });

        UnboundedReceiverStream::new(rx)
    }
}
