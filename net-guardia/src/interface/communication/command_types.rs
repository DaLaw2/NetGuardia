use crate::interface::communication::command::Command;
use crate::interface::communication::message::Message;

// ── System Commands ──────────────────────────────────────────────────

pub struct ChangeEnforceModeCommand {
    pub mode: String,
}

impl Message for ChangeEnforceModeCommand {
    type Response = ();
}
impl Command for ChangeEnforceModeCommand {}
