use crate::interface::communication::command::*;
use crate::interface::communication::event::Event;
use crate::interface::communication::event::EventBroadcaster;
use crate::interface::communication::query::*;
use crate::model::error::misc::MiscError;
use crate::model::error::Error;
use dashmap::DashMap;
use std::any::{Any, TypeId};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Default broadcast channel capacity for event types.
const DEFAULT_CHANNEL_CAPACITY: usize = 256;

/// Inline TypedEventBroadcaster (adapted from MirrorSphere's model).
pub struct TypedEventBroadcaster<E: Event> {
    pub sender: broadcast::Sender<E>,
}

impl<E: Event + 'static> EventBroadcaster for TypedEventBroadcaster<E> {
    fn subscribe_typed(&self) -> Box<dyn Any + Send> {
        Box::new(self.sender.subscribe())
    }

    fn broadcast_event(&self, event: Box<dyn Any + Send>) -> Result<(), Error> {
        let typed_event = *event.downcast::<E>().map_err(|_| MiscError::TypeMismatch)?;
        let _ = self.sender.send(typed_event);
        Ok(())
    }
}

/// Central communication hub using the command/query/event pattern.
/// Adapted from MirrorSphere's CommunicationManager for NetGuardia.
pub struct CommunicationManager {
    command_handlers: DashMap<TypeId, CommandHandlerFn>,
    query_handlers: DashMap<TypeId, QueryHandlerFn>,
    event_broadcasters: DashMap<TypeId, Box<dyn EventBroadcaster>>,
    channel_capacity: usize,
}

impl CommunicationManager {
    pub fn new() -> Self {
        Self {
            command_handlers: DashMap::new(),
            query_handlers: DashMap::new(),
            event_broadcasters: DashMap::new(),
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }

    pub fn with_capacity(channel_capacity: usize) -> Self {
        Self {
            command_handlers: DashMap::new(),
            query_handlers: DashMap::new(),
            event_broadcasters: DashMap::new(),
            channel_capacity,
        }
    }

    pub fn with_service<S: Send + Sync + 'static>(
        self: Arc<Self>,
        service: Arc<S>,
    ) -> ServiceRegistrar<S> {
        ServiceRegistrar::new(service, self)
    }

    pub fn register_command_handler<C: Command + 'static>(
        &self,
        handler: Arc<dyn CommandHandler<C> + Send + Sync>,
    ) {
        let type_id = TypeId::of::<C>();
        let boxed_handler: CommandHandlerFn = Box::new(move |command: Box<dyn Any + Send>| {
            let handler = handler.clone();
            Box::pin(async move {
                let command = *command
                    .downcast::<C>()
                    .map_err(|_| MiscError::TypeMismatch)?;
                handler.handle_command(command).await
            }) as CommandFuture
        });

        self.command_handlers.insert(type_id, boxed_handler);
    }

    pub async fn send_command<C: Command + 'static>(&self, command: C) -> Result<(), Error> {
        let type_id = TypeId::of::<C>();
        if let Some(handler) = self.command_handlers.get(&type_id) {
            handler(Box::new(command)).await
        } else {
            Err(MiscError::HandlerNotFound)?
        }
    }

    pub fn register_query_handler<Q: Query + 'static>(
        &self,
        handler: Arc<dyn QueryHandler<Q> + Send + Sync>,
    ) {
        let type_id = TypeId::of::<Q>();
        let boxed_handler: QueryHandlerFn = Box::new(move |query: Box<dyn Any + Send>| {
            let handler = handler.clone();
            Box::pin(async move {
                let query = *query.downcast::<Q>().map_err(|_| MiscError::TypeMismatch)?;
                let response = handler.handle_query(query).await?;
                Ok(Box::new(response) as Box<dyn Any + Send>)
            }) as QueryFuture
        });

        self.query_handlers.insert(type_id, boxed_handler);
    }

    pub async fn send_query<Q: Query + 'static>(&self, query: Q) -> Result<Q::Response, Error> {
        let type_id = TypeId::of::<Q>();
        if let Some(handler) = self.query_handlers.get(&type_id) {
            let response = handler(Box::new(query)).await?;
            Ok(*response
                .downcast::<Q::Response>()
                .map_err(|_| MiscError::TypeMismatch)?)
        } else {
            Err(MiscError::HandlerNotFound)?
        }
    }

    pub fn register_event_type<E: Event + 'static>(&self) {
        let type_id = TypeId::of::<E>();
        let (tx, _) = broadcast::channel::<E>(self.channel_capacity);
        let broadcaster = TypedEventBroadcaster { sender: tx };
        self.event_broadcasters
            .insert(type_id, Box::new(broadcaster));
    }

    pub fn subscribe_event<E: Event + 'static>(&self) -> Result<broadcast::Receiver<E>, Error> {
        let type_id = TypeId::of::<E>();
        let broadcaster = self
            .event_broadcasters
            .get(&type_id)
            .ok_or(MiscError::TypeNotRegistered)?;
        let receiver_box = broadcaster.subscribe_typed();
        let receiver = *receiver_box
            .downcast::<broadcast::Receiver<E>>()
            .map_err(|_| MiscError::TypeMismatch)?;
        Ok(receiver)
    }

    pub async fn publish_event<E: Event + 'static>(&self, event: E) -> Result<(), Error> {
        let type_id = TypeId::of::<E>();
        let broadcaster = self
            .event_broadcasters
            .get(&type_id)
            .ok_or(MiscError::TypeNotRegistered)?;
        broadcaster.broadcast_event(Box::new(event))
    }

    pub fn clear_handlers(&self) {
        self.command_handlers.clear();
        self.query_handlers.clear();
        self.event_broadcasters.clear();
    }
}

/// Fluent builder for registering a service's command/query/event handlers.
pub struct ServiceRegistrar<S> {
    service: Arc<S>,
    comm: Arc<CommunicationManager>,
}

impl<S: Send + Sync + 'static> ServiceRegistrar<S> {
    fn new(service: Arc<S>, comm: Arc<CommunicationManager>) -> Self {
        Self { service, comm }
    }

    pub fn command<C: Command + 'static>(self) -> Self
    where
        S: CommandHandler<C>,
    {
        let handler: Arc<dyn CommandHandler<C> + Send + Sync> = self.service.clone();
        self.comm.register_command_handler::<C>(handler);
        self
    }

    pub fn query<Q: Query + 'static>(self) -> Self
    where
        S: QueryHandler<Q>,
    {
        let handler: Arc<dyn QueryHandler<Q> + Send + Sync> = self.service.clone();
        self.comm.register_query_handler::<Q>(handler);
        self
    }

    pub fn event<E: Event + 'static>(self) -> Self {
        self.comm.register_event_type::<E>();
        self
    }

    pub fn build(self) -> Arc<CommunicationManager> {
        self.comm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::communication::message::Message;
    use crate::interface::communication::command::Command;
    use crate::interface::communication::query::Query;
    use crate::interface::communication::event::Event;
    use async_trait::async_trait;

    // ── Test Command ─────────────────────────────────────────────────

    struct TestCommand {
        value: String,
    }

    impl Message for TestCommand {
        type Response = ();
    }
    impl Command for TestCommand {}

    struct TestCommandHandler {
        received: Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl CommandHandler<TestCommand> for TestCommandHandler {
        async fn handle_command(&self, command: TestCommand) -> Result<(), Error> {
            self.received.lock().unwrap().push(command.value);
            Ok(())
        }
    }

    // ── Test Query ───────────────────────────────────────────────────

    struct TestQuery {
        input: i32,
    }

    impl Message for TestQuery {
        type Response = i32;
    }
    impl Query for TestQuery {}

    struct TestQueryHandler;

    #[async_trait]
    impl QueryHandler<TestQuery> for TestQueryHandler {
        async fn handle_query(&self, query: TestQuery) -> Result<i32, Error> {
            Ok(query.input * 2)
        }
    }

    // ── Test Event ───────────────────────────────────────────────────

    #[derive(Debug, Clone)]
    struct TestEvent {
        message: String,
    }
    impl Event for TestEvent {}

    // ── Tests ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_command_dispatch() {
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let handler = Arc::new(TestCommandHandler { received: received.clone() });

        let comm = Arc::new(CommunicationManager::new());
        comm.register_command_handler::<TestCommand>(handler);

        comm.send_command(TestCommand { value: "hello".into() }).await.unwrap();

        let msgs = received.lock().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0], "hello");
    }

    #[tokio::test]
    async fn test_command_not_found() {
        let comm = CommunicationManager::new();
        let result = comm.send_command(TestCommand { value: "nope".into() }).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_query_dispatch() {
        let handler = Arc::new(TestQueryHandler);
        let comm = Arc::new(CommunicationManager::new());
        comm.register_query_handler::<TestQuery>(handler);

        let result = comm.send_query(TestQuery { input: 21 }).await.unwrap();
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_query_not_found() {
        let comm = CommunicationManager::new();
        let result = comm.send_query(TestQuery { input: 1 }).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_event_pub_sub() {
        let comm = CommunicationManager::new();
        comm.register_event_type::<TestEvent>();

        let mut receiver = comm.subscribe_event::<TestEvent>().unwrap();

        comm.publish_event(TestEvent { message: "ping".into() }).await.unwrap();

        let event = receiver.recv().await.unwrap();
        assert_eq!(event.message, "ping");
    }

    #[tokio::test]
    async fn test_event_not_registered() {
        let comm = CommunicationManager::new();
        let result = comm.subscribe_event::<TestEvent>();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_event_multiple_subscribers() {
        let comm = CommunicationManager::new();
        comm.register_event_type::<TestEvent>();

        let mut rx1 = comm.subscribe_event::<TestEvent>().unwrap();
        let mut rx2 = comm.subscribe_event::<TestEvent>().unwrap();

        comm.publish_event(TestEvent { message: "broadcast".into() }).await.unwrap();

        assert_eq!(rx1.recv().await.unwrap().message, "broadcast");
        assert_eq!(rx2.recv().await.unwrap().message, "broadcast");
    }

    #[tokio::test]
    async fn test_service_registrar() {
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let handler = Arc::new(TestCommandHandler { received: received.clone() });

        let comm = Arc::new(CommunicationManager::new());
        let _comm = comm.clone()
            .with_service(handler)
            .command::<TestCommand>()
            .build();

        comm.send_command(TestCommand { value: "via_registrar".into() }).await.unwrap();

        let msgs = received.lock().unwrap();
        assert_eq!(msgs[0], "via_registrar");
    }

    #[test]
    fn test_clear_handlers() {
        let comm = CommunicationManager::new();
        comm.register_event_type::<TestEvent>();
        assert!(comm.subscribe_event::<TestEvent>().is_ok());

        comm.clear_handlers();
        assert!(comm.subscribe_event::<TestEvent>().is_err());
    }
}
