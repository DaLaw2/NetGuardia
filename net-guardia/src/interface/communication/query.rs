use crate::interface::communication::message::Message;
use crate::model::error::Error;
use async_trait::async_trait;
use std::any::Any;
use std::future::Future;
use std::pin::Pin;

pub type QueryFuture = Pin<Box<dyn Future<Output = Result<Box<dyn Any + Send>, Error>> + Send + 'static>>;
pub type QueryHandlerFn = Box<dyn Fn(Box<dyn Any + Send>) -> QueryFuture + Send + Sync>;

pub trait Query: Message {}

#[async_trait]
pub trait QueryHandler<Q: Query> {
    async fn handle_query(&self, query: Q) -> Result<Q::Response, Error>;
}
