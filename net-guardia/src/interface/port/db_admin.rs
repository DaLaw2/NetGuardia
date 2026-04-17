use crate::model::error::Error;

/// Persistence technical service — cross-aggregate atomic business operations
/// and database-wide administration (migration, encryption, backup).
///
/// The atomic operations exposed here each span multiple aggregates in one
/// SQLite transaction. Rather than expose a generic `with_transaction`
/// primitive (which cannot be used through a trait object because Rust
/// forbids generic methods on dyn traits), each cross-aggregate use case
/// gets a dedicated business method.
///
/// The five tx points identified during M2 design (see
/// `docs/strategy/debate/v12-architecture-review/M2_CARVE_PLAN.md` §4b):
///
/// | # | Use case | Method |
/// |---|---|---|
/// | tx-1 | SOAR block commit (soar_block_rules + acl_rules) | `commit_soar_block_to_db` |
/// | tx-2 | TTL unblock (acl_rules delete + soar row mark) | `commit_soar_unblock_to_db` |
/// | tx-3 | Manual unblock (same as tx-2) | `commit_soar_unblock_to_db` |
/// | tx-4 | Playbook create + conditions + actions | `insert_playbook_atomic` on SoarRepo |
/// | tx-5 | Playbook update + replace conditions/actions | `update_playbook_atomic` on SoarRepo |
pub trait DbAdminRepo: Send + Sync {
    /// tx-1 — Atomically record a SOAR-driven IP block to both
    /// `soar_block_rules` and `acl_rules`. Returns the new
    /// `soar_block_rules.id`. Callers are responsible for eBPF rollback if
    /// this fails.
    fn commit_soar_block_to_db(
        &self,
        source_ip: &str,
        ip_version: u8,
        playbook_id: i64,
        expires_at: &str,
    ) -> Result<i64, Error>;

    /// tx-2 / tx-3 — Atomically clear a SOAR-driven IP block: removes the
    /// corresponding `acl_rules` row (if present) and marks the
    /// `soar_block_rules` row as unblocked. Callers handle eBPF unblock
    /// separately.
    fn commit_soar_unblock_to_db(&self, soar_block_id: i64, ip_version: u8, source_ip: &str) -> Result<(), Error>;
}
