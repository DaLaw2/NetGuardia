use std::future::Future;
use std::time::Duration;

use macros::log;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::common::error::system::SystemError;

#[derive(Default)]
pub struct Lifecycle {
    graceful_tasks: Vec<NamedGracefulTask>,
    tasks: Vec<NamedTask>,
}

struct NamedGracefulTask {
    name: &'static str,
    tx: oneshot::Sender<()>,
    handle: JoinHandle<()>,
}

struct NamedTask {
    name: &'static str,
    handle: JoinHandle<()>,
}

impl Lifecycle {
    const GRACEFUL_TIMEOUT: Duration = Duration::from_secs(5);

    pub fn graceful(&mut self, name: &'static str, tx: oneshot::Sender<()>, handle: JoinHandle<()>) {
        self.graceful_tasks.push(NamedGracefulTask { name, tx, handle });
    }

    pub fn spawn<F>(&mut self, name: &'static str, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.track(name, tokio::spawn(future));
    }

    pub fn track(&mut self, name: &'static str, handle: JoinHandle<()>) {
        self.tasks.push(NamedTask { name, handle });
    }

    pub async fn terminate(&mut self) {
        let mut graceful_tasks = Vec::new();
        for task in self.graceful_tasks.drain(..) {
            if task.tx.send(()).is_err() {
                log!(SystemError::UnexpectedError(format!(
                    "failed to signal graceful shutdown for '{}'",
                    task.name
                )));
            }
            graceful_tasks.push(NamedTask {
                name: task.name,
                handle: task.handle,
            });
        }

        for mut task in graceful_tasks {
            match timeout(Self::GRACEFUL_TIMEOUT, &mut task.handle).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) if err.is_cancelled() => {}
                Ok(Err(err)) => {
                    log!(SystemError::UnexpectedError(format!(
                        "background task '{}' failed during graceful shutdown: {err}",
                        task.name
                    )));
                }
                Err(_) => {
                    task.handle.abort();
                    if let Err(err) = task.handle.await
                        && !err.is_cancelled()
                    {
                        log!(SystemError::UnexpectedError(format!(
                            "background task '{}' failed after graceful shutdown timeout: {err}",
                            task.name
                        )));
                    }
                }
            }
        }

        for task in self.tasks.drain(..) {
            task.handle.abort();
            if let Err(err) = task.handle.await
                && !err.is_cancelled()
            {
                log!(SystemError::UnexpectedError(format!(
                    "background task '{}' failed during shutdown: {err}",
                    task.name
                )));
            }
        }
    }
}
