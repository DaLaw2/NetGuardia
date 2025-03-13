use crate::model::alert::Alert;
use actix::prelude::*;
use actix_web_actors::ws;
use tokio::sync::broadcast;

pub struct AlertWebSocket {
    pub(crate) handle: Option<SpawnHandle>,
    pub(crate) broadcast_rx: broadcast::Receiver<Alert>,
}

impl AlertWebSocket {
    fn handle_alert(&mut self, ctx: &mut <Self as Actor>::Context) {
        let mut rx = self.broadcast_rx.resubscribe();

        let fut = async move {
            match rx.recv().await {
                Ok(alert) => Some(alert),
                Err(_) => None,
            }
        };

        let handle = ctx.spawn(fut.into_actor(self).map(|result, act, ctx| {
            if let Some(alert) = result {
                if let Ok(json) = serde_json::to_string(&alert) {
                    ctx.text(json);
                }
                act.handle_alert(ctx);
            }
        }));

        self.handle = Some(handle);
    }
}

impl Actor for AlertWebSocket {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.handle_alert(ctx);
    }

    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        if let Some(handle) = self.handle.take() {
            ctx.cancel_future(handle);
        }
        Running::Stop
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for AlertWebSocket {
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
