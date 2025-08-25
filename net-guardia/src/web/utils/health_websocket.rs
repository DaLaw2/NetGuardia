use crate::core::health::SystemHealthMetrics;
use actix::prelude::*;
use actix_web_actors::ws;
use tokio::sync::broadcast;

pub struct SystemHealthWebSocket {
    pub handle: Option<SpawnHandle>,
    pub broadcast_rx: broadcast::Receiver<SystemHealthMetrics>,
}

impl Actor for SystemHealthWebSocket {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.handle_metrics(ctx);
    }

    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        if let Some(handle) = self.handle.take() {
            ctx.cancel_future(handle);
        }
        Running::Stop
    }
}

impl SystemHealthWebSocket {
    fn handle_metrics(&mut self, ctx: &mut <Self as Actor>::Context) {
        let mut rx = self.broadcast_rx.resubscribe();

        let fut = async move {
            match rx.recv().await {
                Ok(metrics) => Some(metrics),
                Err(_) => None,
            }
        };

        let handle = ctx.spawn(fut.into_actor(self).map(|result, act, ctx| {
            if let Some(metrics) = result {
                if let Ok(json) = serde_json::to_string(&metrics) {
                    ctx.text(json);
                }
                act.handle_metrics(ctx);
            }
        }));

        self.handle = Some(handle);
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for SystemHealthWebSocket {
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