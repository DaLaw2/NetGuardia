use std::sync::Arc;

use serde::Serialize;

use crate::common::error::Error;
use crate::common::error::codec::CodecError;
use crate::core::identity::user_service::parse_permissions;
use crate::domain::identity::auth::{GROUP_ADMIN, GROUP_VIEWER};
use crate::domain::identity::error::GroupError;
use crate::domain::identity::user::{GroupMemberView, UserGroupView};
use crate::interface::identity::auth_repo::UserGroupRepo;

#[derive(Serialize)]
pub struct GroupMemberResponse {
    pub id: i64,
    pub username: String,
}

#[derive(Serialize)]
pub struct GroupListResponse {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub permissions: serde_json::Value,
    pub created_at: String,
    pub members: Vec<GroupMemberResponse>,
}

#[derive(Serialize)]
pub struct GroupDetailResponse {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub permissions: serde_json::Value,
    pub created_at: String,
    pub members: Vec<i64>,
}

#[derive(Serialize)]
pub struct GroupMutationResponse {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub permissions: serde_json::Value,
}

pub struct GroupService {
    db: Arc<dyn UserGroupRepo>,
}

impl GroupService {
    pub fn new(db: Arc<dyn UserGroupRepo>) -> Self {
        Self { db }
    }

    pub async fn list_groups(&self) -> Result<Vec<GroupListResponse>, Error> {
        let groups = self.db.list_user_groups().await?;
        let mut result = Vec::with_capacity(groups.len());
        for group in groups {
            let permissions = parse_permissions(&group.permissions)?;
            let member_views = self.db.list_group_members(group.id).await?;
            let members = member_views.into_iter().map(group_member_response).collect();
            result.push(GroupListResponse {
                id: group.id,
                name: group.name,
                description: group.description,
                permissions,
                created_at: group.created_at,
                members,
            });
        }
        Ok(result)
    }

    pub async fn create_group(
        &self,
        name: Option<&str>,
        description: Option<&str>,
        permissions: Option<&serde_json::Value>,
    ) -> Result<GroupMutationResponse, GroupError> {
        let name = match name {
            Some(name) if !name.is_empty() => name,
            _ => return Err(GroupError::Validation("Group name is required".to_string())),
        };
        let description = description.unwrap_or("");
        let (permissions, permissions_json) = permission_array_json(permissions, "[]")?;

        let id = self
            .db
            .create_user_group(name, description, &permissions)
            .await
            .map_err(GroupError::Conflict)?;

        Ok(GroupMutationResponse {
            id,
            name: name.to_string(),
            description: description.to_string(),
            permissions: permissions_json,
        })
    }

    pub async fn get_group(&self, group_id: i64) -> Result<Option<GroupDetailResponse>, Error> {
        let Some(group) = self.db.get_user_group(group_id).await? else {
            return Ok(None);
        };
        let permissions = parse_permissions(&group.permissions)?;
        let members = self.db.list_group_member_ids(group_id).await?;
        Ok(Some(group_detail_response(group, permissions, members)))
    }

    pub async fn update_group(
        &self,
        group_id: i64,
        name: Option<&str>,
        description: Option<&str>,
        permissions: Option<&serde_json::Value>,
    ) -> Result<GroupMutationResponse, GroupError> {
        let existing = self
            .db
            .get_user_group(group_id)
            .await
            .map_err(GroupError::Internal)?
            .ok_or_else(|| GroupError::NotFound("Group not found".to_string()))?;

        if is_builtin_group(&existing.name) {
            return Err(GroupError::Forbidden("Cannot modify built-in groups".to_string()));
        }

        let name = name.unwrap_or(&existing.name).to_string();
        let description = description.unwrap_or(&existing.description).to_string();
        let (permissions, permissions_json) = permission_array_json(permissions, &existing.permissions)?;

        self.db
            .update_user_group(group_id, &name, &description, &permissions)
            .await
            .map_err(GroupError::Internal)?;

        Ok(GroupMutationResponse {
            id: group_id,
            name,
            description,
            permissions: permissions_json,
        })
    }

    pub async fn delete_group(&self, group_id: i64) -> Result<bool, GroupError> {
        let group = self.db.get_user_group(group_id).await.map_err(GroupError::Internal)?;
        if let Some(group) = group.as_ref()
            && is_builtin_group(&group.name)
        {
            return Err(GroupError::Forbidden("Cannot delete built-in groups".to_string()));
        }

        self.db.delete_user_group(group_id).await.map_err(GroupError::Internal)
    }
}

fn group_member_response(member: GroupMemberView) -> GroupMemberResponse {
    GroupMemberResponse {
        id: member.id,
        username: member.username,
    }
}

fn group_detail_response(
    group: UserGroupView,
    permissions: serde_json::Value,
    members: Vec<i64>,
) -> GroupDetailResponse {
    GroupDetailResponse {
        id: group.id,
        name: group.name,
        description: group.description,
        permissions,
        created_at: group.created_at,
        members,
    }
}

fn is_builtin_group(name: &str) -> bool {
    name == GROUP_ADMIN || name == GROUP_VIEWER
}

fn permission_array_json(
    permissions: Option<&serde_json::Value>,
    default: &str,
) -> Result<(String, serde_json::Value), GroupError> {
    match permissions {
        Some(value) => {
            let permissions = serde_json::from_value::<Vec<String>>(value.clone())
                .map_err(|_| GroupError::Validation("Permissions must be an array of strings".to_string()))?;
            let json = serde_json::to_string(&permissions)
                .map_err(|err| GroupError::Internal(CodecError::SerializeFailed(err)))?;
            let value = serde_json::Value::Array(permissions.into_iter().map(serde_json::Value::String).collect());
            Ok((json, value))
        }
        None => Ok((
            default.to_string(),
            parse_permissions(default).map_err(GroupError::Internal)?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::adapter::identity::password_hasher::Argon2PasswordHasher;
    use crate::adapter::persistence::Database;
    use crate::domain::identity::auth::{GROUP_VIEWER, ROLE_VIEWER};
    use crate::interface::identity::auth_repo::UserGroupRepo;
    use crate::interface::identity::password_hasher::PasswordHasher;

    async fn group_service_fixture() -> (Arc<Database>, GroupService) {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        let svc = GroupService::new(db.clone() as Arc<dyn UserGroupRepo>);
        (db, svc)
    }

    async fn create_viewer(db: &Database, username: &str, password: &str) -> i64 {
        let hasher = Argon2PasswordHasher;
        let hash = hasher.hash_password(password).expect("hash");
        let user_id = db
            .insert_user(username, &hash, ROLE_VIEWER, false)
            .await
            .expect("insert user");
        let viewer_group = db
            .list_user_groups()
            .await
            .expect("groups")
            .into_iter()
            .find(|g| g.name == GROUP_VIEWER)
            .expect("viewer group");
        db.set_user_groups(user_id, &[viewer_group.id])
            .await
            .expect("assign viewer group");
        user_id
    }

    #[tokio::test]
    async fn group_workflows_parse_permissions_and_manage_membership() {
        let (db, svc) = group_service_fixture().await;
        let user_id = create_viewer(&db, "alice", "Correct Horse 123!").await;
        let permissions = serde_json::json!(["dashboard:view"]);

        let created = svc
            .create_group(Some("operators"), Some("Ops"), Some(&permissions))
            .await
            .expect("create group");
        assert_eq!(created.name, "operators");
        assert_eq!(created.permissions, permissions);

        db.set_user_groups(user_id, &[created.id]).await.expect("set groups");

        let detail = svc
            .get_group(created.id)
            .await
            .expect("get group")
            .expect("group exists");
        assert_eq!(detail.members, vec![user_id]);

        let updated_permissions = serde_json::json!(["dashboard:view", "audit:read"]);
        let updated = svc
            .update_group(created.id, Some("operators2"), None, Some(&updated_permissions))
            .await
            .expect("update group");
        assert_eq!(updated.name, "operators2");
        assert_eq!(updated.permissions, updated_permissions);

        let groups = svc.list_groups().await.expect("list groups");
        assert!(groups.iter().any(|group| group.id == created.id));

        assert!(svc.delete_group(created.id).await.expect("delete group"));
        assert!(db.get_user_group(created.id).await.expect("get deleted").is_none());
    }

    #[tokio::test]
    async fn group_permissions_must_be_string_arrays() {
        let (_db, svc) = group_service_fixture().await;

        let create_err = match svc
            .create_group(Some("operators"), None, Some(&serde_json::json!([1])))
            .await
        {
            Ok(_) => panic!("numeric permissions must be rejected"),
            Err(err) => err,
        };
        assert!(matches!(create_err, GroupError::Validation { .. }));

        let created = svc
            .create_group(Some("operators"), None, Some(&serde_json::json!(["dashboard:read"])))
            .await
            .expect("create group");
        let update_err = match svc
            .update_group(created.id, None, None, Some(&serde_json::json!("dashboard:read")))
            .await
        {
            Ok(_) => panic!("non-array permissions must be rejected"),
            Err(err) => err,
        };

        assert!(matches!(update_err, GroupError::Validation { .. }));
    }
}
