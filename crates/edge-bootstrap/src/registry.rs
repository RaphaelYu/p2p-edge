use crate::error::BootstrapError;
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeStatus {
    Pending,
    Active,
    Revoked,
    Rejected,
}

impl NodeStatus {
    fn as_str(&self) -> &'static str {
        match self {
            NodeStatus::Pending => "Pending",
            NodeStatus::Active => "Active",
            NodeStatus::Revoked => "Revoked",
            NodeStatus::Rejected => "Rejected",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Pending" => Some(NodeStatus::Pending),
            "Active" => Some(NodeStatus::Active),
            "Revoked" => Some(NodeStatus::Revoked),
            "Rejected" => Some(NodeStatus::Rejected),
            _ => None,
        }
    }
}

fn is_allowed_transition(from: NodeStatus, to: NodeStatus) -> bool {
    matches!(
        (from, to),
        (NodeStatus::Pending, NodeStatus::Active)
            | (NodeStatus::Pending, NodeStatus::Rejected)
            | (NodeStatus::Active, NodeStatus::Revoked)
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeRecord {
    pub peer_id: String,
    pub addrs: Vec<String>,
    pub tags: Vec<String>,
    pub weight: u16,
    pub status: NodeStatus,
    pub operator_id: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_approved_at: Option<i64>,
    pub revoked_reason: Option<String>,
    pub pubkey_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditAction {
    Enroll,
    Approve,
    Reject,
    Revoke,
    UpdateAddrs,
}

impl AuditAction {
    fn as_str(&self) -> &'static str {
        match self {
            AuditAction::Enroll => "ENROLL",
            AuditAction::Approve => "APPROVE",
            AuditAction::Reject => "REJECT",
            AuditAction::Revoke => "REVOKE",
            AuditAction::UpdateAddrs => "UPDATE_ADDRS",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRecord {
    pub id: i64,
    pub ts: i64,
    pub actor: String,
    pub action: AuditAction,
    pub target_peer_id: String,
    pub meta: serde_json::Value,
}

#[derive(Clone)]
pub struct RegistryStore {
    conn: Arc<Mutex<Connection>>,
}

impl RegistryStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BootstrapError> {
        let conn = Connection::open(path)
            .map_err(|e| BootstrapError::Io(std::io::Error::other(e.to_string())))?;
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(|e| BootstrapError::Config(e.to_string()))?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn conn(&self) -> Result<MutexGuard<'_, Connection>, BootstrapError> {
        self.conn
            .lock()
            .map_err(|_| BootstrapError::Config("registry mutex poisoned".to_string()))
    }

    fn init_schema(conn: &Connection) -> Result<(), BootstrapError> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS nodes (
                peer_id TEXT PRIMARY KEY,
                addrs TEXT NOT NULL,
                tags TEXT NOT NULL,
                weight INTEGER NOT NULL,
                status TEXT NOT NULL,
                operator_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_approved_at INTEGER,
                revoked_reason TEXT,
                pubkey_b64 TEXT
            );

            CREATE TABLE IF NOT EXISTS audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target_peer_id TEXT NOT NULL,
                meta TEXT NOT NULL
            );
        "#,
        )
        .map_err(|e| BootstrapError::Config(e.to_string()))?;
        // If the database pre-exists, best-effort add pubkey column without failing startup.
        let _ = conn.execute("ALTER TABLE nodes ADD COLUMN pubkey_b64 TEXT", []);
        Ok(())
    }

    pub fn upsert_pending(
        &self,
        peer_id: &str,
        addrs: Vec<String>,
        operator_id: &str,
        tags: Vec<String>,
        weight: u16,
        pubkey_b64: Option<String>,
    ) -> Result<(), BootstrapError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let addrs_json = serde_json::to_string(&addrs)
            .map_err(|e| BootstrapError::Serialization(e.to_string()))?;
        let tags_json = serde_json::to_string(&tags)
            .map_err(|e| BootstrapError::Serialization(e.to_string()))?;

        {
            let conn = self.conn()?;
            conn.execute(
                r#"
                INSERT INTO nodes (
                    peer_id, addrs, tags, weight, status, operator_id, created_at, updated_at, last_approved_at, revoked_reason, pubkey_b64
                ) VALUES (?1, ?2, ?3, ?4, 'Pending', ?5, ?6, ?6, NULL, NULL, ?7)
                ON CONFLICT(peer_id) DO UPDATE SET
                    addrs=excluded.addrs,
                    tags=excluded.tags,
                    weight=excluded.weight,
                    status='Pending',
                    operator_id=excluded.operator_id,
                    updated_at=excluded.updated_at,
                    revoked_reason=NULL,
                    pubkey_b64=excluded.pubkey_b64
                "#,
                params![peer_id, addrs_json, tags_json, weight as i64, operator_id, now, pubkey_b64],
            )
            .map_err(|e| BootstrapError::Config(e.to_string()))?;
        }

        self.insert_audit(
            AuditAction::Enroll,
            operator_id,
            peer_id,
            serde_json::json!({"addr_count": addrs.len(), "weight": weight}),
        )?;
        Ok(())
    }

    pub fn set_status(
        &self,
        peer_id: &str,
        status: NodeStatus,
        actor: &str,
        reason: Option<String>,
    ) -> Result<(), BootstrapError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let last_approved_at: Option<i64> = matches!(status, NodeStatus::Active).then_some(now);
        let revoked_reason = if matches!(status, NodeStatus::Revoked) {
            reason.clone()
        } else {
            None
        };

        {
            let conn = self.conn()?;
            let current_status: Option<String> = conn
                .query_row(
                    "SELECT status FROM nodes WHERE peer_id = ?1",
                    params![peer_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| BootstrapError::Config(e.to_string()))?;
            let Some(current_status) = current_status else {
                return Err(BootstrapError::Config("peer not found".to_string()));
            };
            let Some(current) = NodeStatus::from_str(&current_status) else {
                return Err(BootstrapError::Config("invalid current status".to_string()));
            };
            if !is_allowed_transition(current, status.clone()) {
                return Err(BootstrapError::Config(
                    "invalid status transition".to_string(),
                ));
            }
            conn.execute(
                r#"
                UPDATE nodes SET
                    status = ?1,
                    updated_at = ?2,
                    last_approved_at = COALESCE(?3, last_approved_at),
                    revoked_reason = ?4
                WHERE peer_id = ?5
                "#,
                params![
                    status.as_str(),
                    now,
                    last_approved_at,
                    revoked_reason,
                    peer_id
                ],
            )
            .map_err(|e| BootstrapError::Config(e.to_string()))?;
        }

        let action = match status {
            NodeStatus::Pending => AuditAction::Enroll,
            NodeStatus::Active => AuditAction::Approve,
            NodeStatus::Revoked => AuditAction::Revoke,
            NodeStatus::Rejected => AuditAction::Reject,
        };
        let mut meta = serde_json::Map::new();
        meta.insert(
            "status".to_string(),
            serde_json::Value::String(status.as_str().to_string()),
        );
        if let Some(reason) = &reason {
            meta.insert(
                "reason".to_string(),
                serde_json::Value::String(reason.clone()),
            );
        }
        self.insert_audit(action, actor, peer_id, serde_json::Value::Object(meta))?;
        Ok(())
    }

    pub fn list_by_status(
        &self,
        status: Option<NodeStatus>,
    ) -> Result<Vec<NodeRecord>, BootstrapError> {
        let conn = self.conn()?;
        let mut stmt = match status {
            Some(_) => conn
                .prepare("SELECT * FROM nodes WHERE status = ?1")
                .map_err(|e| BootstrapError::Config(e.to_string()))?,
            None => conn
                .prepare("SELECT * FROM nodes")
                .map_err(|e| BootstrapError::Config(e.to_string()))?,
        };
        let rows = match status {
            Some(status) => stmt
                .query_map(params![status.as_str()], Self::map_node)
                .map_err(|e| BootstrapError::Config(e.to_string()))?,
            None => stmt
                .query_map([], Self::map_node)
                .map_err(|e| BootstrapError::Config(e.to_string()))?,
        };
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| BootstrapError::Config(e.to_string()))?);
        }
        Ok(out)
    }

    pub fn list_active(&self) -> Result<Vec<NodeRecord>, BootstrapError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT * FROM nodes WHERE status = 'Active'")
            .map_err(|e| BootstrapError::Config(e.to_string()))?;
        let rows = stmt
            .query_map([], Self::map_node)
            .map_err(|e| BootstrapError::Config(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| BootstrapError::Config(e.to_string()))?);
        }
        Ok(out)
    }

    pub fn list_revoked_peer_ids(&self) -> Result<Vec<String>, BootstrapError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT peer_id FROM nodes WHERE status = 'Revoked'")
            .map_err(|e| BootstrapError::Config(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| BootstrapError::Config(e.to_string()))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row.map_err(|e| BootstrapError::Config(e.to_string()))?);
        }
        Ok(ids)
    }

    pub fn get(&self, peer_id: &str) -> Result<Option<NodeRecord>, BootstrapError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT * FROM nodes WHERE peer_id = ?1")
            .map_err(|e| BootstrapError::Config(e.to_string()))?;
        let rec = stmt
            .query_row(params![peer_id], Self::map_node)
            .optional()
            .map_err(|e| BootstrapError::Config(e.to_string()))?;
        Ok(rec)
    }

    fn map_node(row: &Row<'_>) -> rusqlite::Result<NodeRecord> {
        let status_str: String = row.get("status")?;
        let status = NodeStatus::from_str(&status_str).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid status",
                )),
            )
        })?;
        let addrs_json: String = row.get("addrs")?;
        let tags_json: String = row.get("tags")?;
        let addrs: Vec<String> = serde_json::from_str(&addrs_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?;
        let tags: Vec<String> = serde_json::from_str(&tags_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?;

        Ok(NodeRecord {
            peer_id: row.get("peer_id")?,
            addrs,
            tags,
            weight: row.get::<_, i64>("weight")? as u16,
            status,
            operator_id: row.get("operator_id")?,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
            last_approved_at: row.get("last_approved_at")?,
            revoked_reason: row.get("revoked_reason")?,
            pubkey_b64: row.get("pubkey_b64")?,
        })
    }

    fn insert_audit(
        &self,
        action: AuditAction,
        actor: &str,
        target_peer_id: &str,
        meta: serde_json::Value,
    ) -> Result<(), BootstrapError> {
        let ts = OffsetDateTime::now_utc().unix_timestamp();
        let meta_str = serde_json::to_string(&meta)
            .map_err(|e| BootstrapError::Serialization(e.to_string()))?;
        let conn = self.conn()?;
        conn.execute(
                "INSERT INTO audits (ts, actor, action, target_peer_id, meta) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![ts, actor, action.as_str(), target_peer_id, meta_str],
            )
            .map_err(|e| BootstrapError::Config(e.to_string()))?;
        Ok(())
    }
}
