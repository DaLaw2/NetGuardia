use actix::prelude::*;
use actix_web_actors::ws;

pub struct IPv4FlowWebSocket {
    pub interval: Option<SpawnHandle>,
}

impl Actor for IPv4FlowWebSocket {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {

    }

    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        Running::Stop
    }
}

pub struct IPv6FlowWebSocket {
    pub interval: Option<SpawnHandle>,
}

impl Actor for IPv6FlowWebSocket {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {

    }

    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        Running::Stop
    }
}