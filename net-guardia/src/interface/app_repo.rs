use crate::interface::acl::AclRepo;
use crate::interface::api_key::ApiKeyRepo;
use crate::interface::audit::AuditRepo;
use crate::interface::db_admin::DbAdminRepo;
use crate::interface::enforcement::EnforcementRepo;
use crate::interface::identity::{LoginAttemptRepo, UserGroupRepo, UserRepo};
use crate::interface::setting::SettingRepo;
use crate::interface::soar::SoarRepo;
use crate::interface::stats::StatsRepo;

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
    + UserRepo
    + UserGroupRepo
    + LoginAttemptRepo
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
        + UserRepo
        + UserGroupRepo
        + LoginAttemptRepo
        + SettingRepo
        + SoarRepo
        + StatsRepo
        + Send
        + Sync
        + ?Sized
{
}
