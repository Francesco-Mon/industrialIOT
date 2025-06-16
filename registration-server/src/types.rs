use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommandRequest {
    pub command: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommandResponse {
    pub status: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: String,
    pub status: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}