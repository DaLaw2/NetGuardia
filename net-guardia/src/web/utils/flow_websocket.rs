use crate::core::config_manager::ConfigManager;
use crate::core::monitor::Monitor;
use crate::model::flow_type::{IPv4FlowType, IPv6FlowType};
use actix::prelude::*;
use actix_web_actors::ws;
use std::time::Duration;

pub struct IPv4FlowWebSocket {
    pub flow_type: IPv4FlowType,
    pub interval: Option<SpawnHandle>,
}

impl Actor for IPv4FlowWebSocket {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let config = ConfigManager::now_blocking();
        let refresh_interval = Duration::from_secs(config.refresh_interval);
        let interval = ctx.run_interval(refresh_interval, |actor, ctx| {
            let flow_type = actor.flow_type.clone();
            let future = async move {
                Monitor::get_ipv4_flow_data(flow_type).await
            };
            ctx.wait(future.into_actor(actor).map(|flow_data, _, ctx| {
                if let Ok(json) = serde_json::to_string(&flow_data) {
                    ctx.text(json);
                }
            }));
        });
        self.interval = Some(interval);
    }

    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        if let Some(interval) = self.interval.take() {
            ctx.cancel_future(interval);
        }
        Running::Stop
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for IPv4FlowWebSocket {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => ctx.pong(&msg),
            Ok(ws::Message::Pong(_)) => (),
            Ok(ws::Message::Text(text)) => ctx.text(text),
            Ok(ws::Message::Binary(bin)) => ctx.binary(bin),
            Ok(ws::Message::Close(reason)) => ctx.close(reason),
            _ => (),
        }
    }
}

pub struct IPv6FlowWebSocket {
    pub flow_type: IPv6FlowType,
    pub interval: Option<SpawnHandle>,
}

impl Actor for IPv6FlowWebSocket {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let config = ConfigManager::now_blocking();
        let refresh_interval = Duration::from_secs(config.refresh_interval);
        let interval = ctx.run_interval(refresh_interval, |actor, ctx| {
            let flow_type = actor.flow_type.clone();
            let future = async move {
                Monitor::get_ipv6_flow_data(flow_type).await
            };
            ctx.wait(future.into_actor(actor).map(|flow_data, _, ctx| {
                if let Ok(json) = serde_json::to_string(&flow_data) {
                    ctx.text(json);
                }
            }));
        });
        self.interval = Some(interval);
    }

    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        if let Some(interval) = self.interval.take() {
            ctx.cancel_future(interval);
        }
        Running::Stop
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for IPv6FlowWebSocket {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => ctx.pong(&msg),
            Ok(ws::Message::Pong(_)) => (),
            Ok(ws::Message::Text(text)) => ctx.text(text),
            Ok(ws::Message::Binary(bin)) => ctx.binary(bin),
            Ok(ws::Message::Close(reason)) => ctx.close(reason),
            _ => (),
        }
    }
}
