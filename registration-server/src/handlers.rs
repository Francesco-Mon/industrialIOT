use crate::types::{CommandResponse, DeviceInfo};
use chrono::Utc;
use etcd_client::Client;
use tracing::{error, info, instrument, warn};
use etcd_client::{Compare, CompareOp, Txn, TxnOp};

// --- Gestione specifica dei comandi (con logging) ---

#[instrument(skip(etcd), fields(device_id = %device_id))]
pub async fn handle_registration(device_id: String, etcd: &mut Client) -> CommandResponse {
    let key = format!("devices/{}", device_id);
    info!("Processo di registrazione atomica...");

    // Prepara i dati per il nuovo dispositivo
    let now = Utc::now();
    let device_info = DeviceInfo {
        device_id: device_id.clone(),
        status: "registered".to_string(),
        first_seen: now,
        last_seen: now,
    };
    let value = serde_json::to_string(&device_info).unwrap();

    // Crea una transazione atomica:
    // "SE la versione della chiave è 0 (cioè non esiste), ALLORA esegui l'operazione PUT"
    let txn = Txn::new()
        .when(vec![Compare::version(key.clone(), CompareOp::Equal, 0)])
        .and_then(vec![TxnOp::put(key, value, None)]);
    
    // Esegui la transazione
    match etcd.txn(txn).await {
        Ok(txn_resp) => {
            // `succeeded` è true se la condizione 'when' è stata soddisfatta
            if txn_resp.succeeded() {
                info!("Dispositivo registrato con successo in etcd via transazione.");
                CommandResponse { status: "ok".to_string(), message: "Registrazione completata con successo.".to_string() }
            } else {
                info!("Dispositivo già esistente, registrazione saltata.");
                CommandResponse { status: "ok".to_string(), message: "Dispositivo già registrato.".to_string() }
            }
        },
        Err(e) => {
            error!(error = %e, "Errore etcd durante la transazione.");
            CommandResponse { status: "error".to_string(), message: "Errore interno del server.".to_string() }
        }
    }
}

#[instrument(skip(etcd), fields(device_id = %device_id))]
pub async fn handle_heartbeat(device_id: String, etcd: &mut Client) -> CommandResponse {
    let key = format!("devices/{}", device_id);
    
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
        warn!("Ricevuto heartbeat da dispositivo non registrato.");
        CommandResponse { status: "error".to_string(), message: "Dispositivo non registrato.".to_string() }
    }
}

// ===================================================================
//  MODULO DI UNIT TEST
// ===================================================================
// Questo blocco viene compilato e eseguito solo con `cargo test`
#[cfg(test)]
mod tests {
    // Importiamo le struct e le funzioni necessarie dal modulo padre
    use super::*;
    use crate::types::{CommandResponse, DeviceInfo};

    // Un test molto semplice per assicurarsi che l'ambiente di test funzioni.
    #[test]
    fn basic_assertion() {
        assert_eq!(2 + 2, 4, "La matematica di base dovrebbe funzionare!");
    }

    // Testiamo che la nostra struct `CommandResponse` si possa creare
    // e che i suoi campi siano corretti. Questo è un vero unit test.
    #[test]
    fn test_command_response_creation() {
        let status = "ok".to_string();
        let message = "Test superato".to_string();

        let response = CommandResponse {
            status: status.clone(),
            message: message.clone(),
        };

        assert_eq!(response.status, status);
        assert_eq!(response.message, message);
    }
    
    // Testiamo la creazione della struct `DeviceInfo`.
    #[test]
    fn test_device_info_creation() {
        let now = Utc::now();
        let info = DeviceInfo {
            device_id: "test-id".to_string(),
            status: "testing".to_string(),
            first_seen: now,
            last_seen: now,
        };

        assert_eq!(info.device_id, "test-id");
        assert_eq!(info.status, "testing");
        assert_eq!(info.first_seen, now);
    }
}