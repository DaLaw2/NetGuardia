use std::any::Any;

use crate::domain::common::error::Error;

pub trait Event: Send + Clone + 'static {}

pub trait EventBroadcaster: Send + Sync {
    fn subscribe_typed(&self) -> Box<dyn Any + Send>;
    fn broadcast_event(&self, event: Box<dyn Any + Send>) -> Result<(), Error>;
}
