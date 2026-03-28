use crate::interface::communication::message::Message;
use crate::interface::communication::query::Query;

// ── System Queries ───────────────────────────────────────────────────

pub struct GetEnforceModeQuery;

impl Message for GetEnforceModeQuery {
    type Response = String;
}
impl Query for GetEnforceModeQuery {}
