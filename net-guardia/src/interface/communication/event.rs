use crate::model::error::Error;
use std::any::Any;

pub trait Event: Send + Clone + 'static {}

pub trait EventBroadcaster: Send + Sync {
    fn subscribe_typed(&self) -> Box<dyn Any + Send>;
    fn broadcast_event(&self, event: Box<dyn Any + Send>) -> Result<(), Error>;
}
