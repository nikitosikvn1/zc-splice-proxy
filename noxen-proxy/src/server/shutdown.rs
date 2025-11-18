use tokio::sync::broadcast;

#[derive(Debug)]
pub struct Shutdown {
    notify: broadcast::Receiver<()>,
}

impl Shutdown {
    pub fn new(notify: broadcast::Receiver<()>) -> Shutdown {
        Self { notify }
    }

    pub async fn recv(&mut self) {
        let _ = self.notify.recv().await;
    }
}
