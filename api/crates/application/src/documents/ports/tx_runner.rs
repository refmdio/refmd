use std::any::Any;
use std::future::Future;
use std::pin::Pin;

use anyhow::anyhow;
use async_trait::async_trait;

use crate::core::ports::storage::storage_projection_queue::StorageProjectionQueueTx;
use crate::documents::ports::document_repository::DocumentRepositoryTx;
use crate::documents::ports::files::files_repository::FilesRepositoryTx;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type BoxedTxResult = Box<dyn Any + Send>;
pub type DocumentsTxFuture<'tx> = BoxFuture<'tx, anyhow::Result<BoxedTxResult>>;
pub type DocumentsTxFn =
    Box<dyn for<'tx> FnOnce(&'tx mut dyn DocumentsTx) -> DocumentsTxFuture<'tx> + Send>;

pub trait DocumentsTx: Send {
    fn documents(&mut self) -> &mut dyn DocumentRepositoryTx;
    fn files(&mut self) -> &mut dyn FilesRepositoryTx;
    fn storage_jobs(&mut self) -> &mut dyn StorageProjectionQueueTx;
}

#[async_trait]
pub trait DocumentsTxRunner: Send + Sync {
    async fn run_boxed(&self, f: DocumentsTxFn) -> anyhow::Result<BoxedTxResult>;
}

pub async fn run_in_tx<T, F>(runner: &dyn DocumentsTxRunner, f: F) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: for<'tx> FnOnce(&'tx mut dyn DocumentsTx) -> BoxFuture<'tx, anyhow::Result<T>>
        + Send
        + 'static,
{
    let mut f = Some(f);
    let result = runner
        .run_boxed(Box::new(move |tx| {
            let f = f
                .take()
                .expect("DocumentsTx closure must be called exactly once");
            Box::pin(async move {
                let out = f(tx).await?;
                Ok(Box::new(out) as BoxedTxResult)
            })
        }))
        .await?;

    result
        .downcast::<T>()
        .map(|v| *v)
        .map_err(|_| anyhow!("documents tx runner output type mismatch"))
}
