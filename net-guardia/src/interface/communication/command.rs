use std::any::Any;
use std::future::Future;
use std::pin::Pin;

use async_trait::async_trait;

use crate::domain::common::error::Error;
use crate::interface::communication::message::Message;

pub type CommandFuture = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'static>>;
pub type CommandHandlerFn = Box<dyn Fn(Box<dyn Any + Send>) -> CommandFuture + Send + Sync>;

pub trait Command: Message<Response = ()> {}

#[async_trait]
pub trait CommandHandler<C: Command> {
    async fn handle_command(&self, command: C) -> Result<(), Error>;
}
