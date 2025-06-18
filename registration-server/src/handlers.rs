use crate::types::{CommandResponse, DeviceInfo};
use chrono::Utc;
use etcd_client::Client;
use tracing::{error, info, instrument, warn};

#[instrument(skip(etcd), fields(device_id = %device_id))]
pub async fn handle_registration(device_id: String, etcd: &mut Client) -> CommandResponse {
    let cert_key = format!("devices/certificates/{}", device_id);
    let info_key = format!("devices/info/{}", device_id);
    info!("Processo di registrazione/verifica...");
    
    match etcd.get(cert_key, None).await {
        Ok(resp) if resp.kvs().is_empty() => {
            warn!("Tentativo di registrazione con un certificato non emesso dalla nostra CA.");
            return CommandResponse { status: "error".to_string(), message: "Certificato non riconosciuto o non autorizzato.".to_string() };
        },
        Err(e) => {
             error!(error = %e, "Errore etcd in lettura certificato.");
             return CommandResponse { status: "error".to_string(), message: "Errore interno.".to_string() };
        }
        _ => {}
    }

    if let Ok(resp) = etcd.get(info_key.clone(), None).await {
        if !resp.kvs().is_empty() {
            info!("Dispositivo già registrato, procedo con heartbeat.");
            return handle_heartbeat(device_id, etcd).await;
        }
    }
    
    info!("Primo contatto da dispositivo autorizzato. Creazione record informativo...");
    let now = Utc::now();
    let device_info = DeviceInfo {
        device_id: device_id.clone(),
        status: "registered".to_string(),
        first_seen: now,
        last_seen: now,
    };
    let value = serde_json::to_string(&device_info).unwrap();
    
    if etcd.put(info_key, value, None).await.is_err() {
        error!("Errore etcd in scrittura info dispositivo.");
        return CommandResponse { status: "error".to_string(), message: "Errore interno.".to_string() };
    }

    info!("Record informativo creato per il dispositivo.");
    CommandResponse { status: "ok".to_string(), message: "Registrazione completata con successo.".to_string() }
}

#[instrument(skip(etcd), fields(device_id = %device_id))]
pub async fn handle_heartbeat(device_id: String, etcd: &mut Client) -> CommandResponse {
    let key = format!("devices/info/{}", device_id);
    
    let get_resp = match etcd.get(key.clone(), None).await {
        Ok(resp) => resp,
        Err(e) => {
            error!(error = %e, "Errore etcd in lettura durante heartbeat.");
            return CommandResponse { status: "error".to_string(), message: "Errore interno.".to_string() };
        }
    };

    if let Some(kv) = get_resp.kvs().first() {
        let mut device_info: DeviceInfo = match serde_json::from_slice(kv.value()) {
            Ok(info) => info,
            Err(e) => {
                error!(error = %e, "Impossibile deserializzare DeviceInfo da etcd.");
                return CommandResponse { status: "error".to_string(), message: "Record dispositivo corrotto.".to_string() };
            }
        };
        
        device_info.last_seen = Utc::now();
        device_info.status = "active".to_string();
        
        let value = serde_json::to_string(&device_info).unwrap();
        match etcd.put(key, value, None).await {
            Ok(_) => CommandResponse { status: "ok".to_string(), message: "Heartbeat ricevuto.".to_string() },
            Err(e) => {
                error!(error = %e, "Errore etcd in scrittura durante heartbeat.");
                CommandResponse { status: "error".to_string(), message: "Errore interno.".to_string() }
            }
        }
    } else {
        warn!("Ricevuto heartbeat da dispositivo non registrato (manca record info).");
        CommandResponse { status: "error".to_string(), message: "Dispositivo non registrato.".to_string() }
    }
}