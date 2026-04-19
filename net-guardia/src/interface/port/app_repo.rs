use super::acl::AclRepo;
use super::api_key::ApiKeyRepo;
use super::audit::AuditRepo;
use super::db_admin::DbAdminRepo;
use super::enforcement::EnforcementRepo;
use super::identity::IdentityRepo;
use super::setting::SettingRepo;
use super::soar::SoarRepo;
use super::stats::StatsRepo;

/// Composition-root supertrait bundling every aggregate Repo trait +
/// `DbAdminRepo`.
///
/// Services that operate on a single aggregate should take the
/// aggregate-specific trait (`Arc<dyn AclRepo>`, `Arc<dyn SoarRepo>`, …) so
/// their dependency surface matches their responsibility. `AppRepo` exists
/// for composition wiring and for legacy call sites that span many
/// aggregates; it is an implementation convenience, not an aggregate
/// definition.
pub trait AppRepo:
    AclRepo
    + ApiKeyRepo
    + AuditRepo
    + DbAdminRepo
    + EnforcementRepo
    + IdentityRepo
    + SettingRepo
    + SoarRepo
    + StatsRepo
    + Send
    + Sync
{
}

impl<T> AppRepo for T where
    T: AclRepo
        + ApiKeyRepo
        + AuditRepo
        + DbAdminRepo
        + EnforcementRepo
        + IdentityRepo
        + SettingRepo
        + SoarRepo
        + StatsRepo
        + Send
        + Sync
        + ?Sized
{
}
