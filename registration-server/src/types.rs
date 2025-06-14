use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// Richiesta di comando dal client
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommandRequest {
    pub command: String,
}

// Risposta del server al client
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommandResponse {
    pub status: String,
    pub message: String,
}

// Struttura dei dati del dispositivo memorizzata in etcd
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: String,
    pub status: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}