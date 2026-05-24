use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

#[derive(Clone)]
pub struct SetupCompleteFlag {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl SetupCompleteFlag {
    pub fn new(complete: bool) -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(complete)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    pub fn mark_complete(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub async fn wait_complete(&self) {
        loop {
            let notified = self.notify.notified();
            if self.is_complete() {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Clone)]
pub struct ReadyFlag(pub Arc<AtomicBool>);

#[derive(Clone)]
pub struct ForceHttpsFlag(pub Arc<AtomicBool>);

#[cfg(test)]
mod tests {
    use tokio::time::{Duration, timeout};

    use super::SetupCompleteFlag;

    #[tokio::test]
    async fn setup_complete_flag_notifies_waiters() {
        let flag = SetupCompleteFlag::new(false);
        let waiter = {
            let flag = flag.clone();
            tokio::spawn(async move {
                flag.wait_complete().await;
            })
        };

        flag.mark_complete();

        match timeout(Duration::from_secs(1), waiter).await {
            Ok(join_result) => assert!(join_result.is_ok()),
            Err(_) => panic!("waiter should be notified"),
        }
    }
}
