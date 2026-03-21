pub trait Message: Send + 'static {
    type Response: Send + 'static;
}
