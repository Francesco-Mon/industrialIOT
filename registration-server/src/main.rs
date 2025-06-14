use std::env;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::{response::IntoResponse, routing::get, Router};
use chrono::{DateTime, Utc};
use etcd_client::Client;
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, instrument, warn};
use tracing_subscriber::{prelude::*, EnvFilter};
use x509_parser::prelude::*;

// --- Strutture Dati (invariate) ---
#[derive(Serialize, Deserialize, Debug)]
struct CommandRequest {
    command: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CommandResponse {
    status: String,
    message: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct DeviceInfo {
    device_id: String,
    status: String,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

// --- Funzioni Helper TLS (invariate) ---
fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    let mut cert_file = BufReader::new(File::open(path)?);
    certs(&mut cert_file).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert")).map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_private_key(path: &Path) -> io::Result<PrivateKey> {
    let mut key_file = BufReader::new(File::open(path)?);
    pkcs8_private_keys(&mut key_file).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid private key")).map(|mut keys| PrivateKey(keys.remove(0)))
}

// --- Funzione Principale (Orchestra l'avvio) ---
#[tokio::main]
async fn main() -> io::Result<()> {
    // Inizializza il logger strutturato
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().json())
        .with(EnvFilter::from_default_env())
        .init();

    info!("Avvio del sistema di registrazione dispositivi.");

    // Avvia l'health check in un task separato
    let health_handle = tokio::spawn(health_check_server());
    
    // Avvia il server principale in un altro task
    let server_handle = tokio::spawn(main_server());

    // Attendi che uno dei due task fallisca. 
    // select! attende il primo branch che si completa.
    tokio::select! {
        res = health_handle => {
            error!(result = ?res, "Il server di Health Check è terminato inaspettatamente.");
        }
        res = server_handle => {
            error!(result = ?res, "Il server principale è terminato inaspettatamente.");
        }
    }

    Ok(())
}

// --- Server HTTP per l'Health Check ---
async fn health_check_server() {
    let app = Router::new().route("/health", get(|| async { "OK" }));
    let addr = SocketAddr::from(([0, 0, 0, 0], 9000));
    info!(address = %addr, "Server di Health Check in ascolto.");
    if let Err(e) = axum::Server::bind(&addr).serve(app.into_make_service()).await {
        error!(error = %e, "Server di Health Check terminato con errore.");
    }
}

// --- Server Principale TCP/TLS ---
async fn main_server() {
    let addr: SocketAddr = "0.0.0.0:8443".parse().unwrap();
    
    // Caricamento configurazione TLS
    let server_certs = load_certs(Path::new("/certs/server.crt")).expect("Impossibile caricare il certificato del server.");
    let server_key = load_private_key(Path::new("/certs/server.key")).expect("Impossibile caricare la chiave del server.");
    let client_ca_cert = load_certs(Path::new("/certs/ca.crt")).expect("Impossibile caricare il certificato della CA.");
    
    let mut client_auth_roots = rustls::RootCertStore::empty();
    for cert in client_ca_cert {
        client_auth_roots.add(&cert).unwrap();
    }
    
    let client_cert_verifier = rustls::server::AllowAnyAuthenticatedClient::new(client_auth_roots);
    let tls_config = Arc::new(rustls::ServerConfig::builder().with_safe_defaults().with_client_cert_verifier(Arc::new(client_cert_verifier)).with_single_cert(server_certs, server_key).unwrap());
    let acceptor = TlsAcceptor::from(tls_config);

    // Connessione a etcd
    let etcd_endpoint = env::var("ETCD_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:2379".to_string());
    info!(endpoint = %etcd_endpoint, "Connessione a etcd...");
    let etcd_client = Client::connect([etcd_endpoint], None).await.expect("Connessione a etcd fallita.");
    info!("Connesso a etcd con successo.");

    let listener = TcpListener::bind(&addr).await.expect("Binding della porta fallito.");
    info!(address = %addr, "Server principale in ascolto.");

    // Loop di accettazione connessioni
    loop {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        info!(%peer_addr, "Nuova connessione ricevuta.");
        
        let acceptor = acceptor.clone();
        let etcd_client_clone = etcd_client.clone();
        
        tokio::spawn(handle_new_connection(stream, acceptor, etcd_client_clone));
    }
}

// --- Gestione di una singola connessione ---
#[instrument(skip_all, fields(peer_addr))]
async fn handle_new_connection(stream: TcpStream, acceptor: TlsAcceptor, mut etcd_client: Client) {
    let peer_addr = stream.peer_addr().map_or_else(|_| "sconosciuto".to_string(), |a| a.to_string());
    tracing::Span::current().record("peer_addr", &peer_addr);

    let stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "Errore durante l'handshake TLS.");
            return;
        }
    };
    
    let (_, server_conn) = stream.get_ref();
    let device_id = match server_conn.peer_certificates() {
        Some(certs) if !certs.is_empty() => match parse_x509_certificate(&certs[0].0) {
            Ok((_, cert)) => cert.subject().iter_common_name().next().map(|cn| cn.as_str().unwrap().to_string()).unwrap_or_else(|| "unknown-device".to_string()),
            Err(_) => "unknown-device-parsing-failed".to_string(),
        },
        _ => "unknown-device-no-cert".to_string(),
    };
    
    info!(%device_id, "Handshake TLS completato.");

    if device_id.starts_with("unknown-device") {
        warn!(%device_id, "Dispositivo non identificabile, chiusura connessione.");
        return;
    }
    
    handle_commands(stream, device_id, &mut etcd_client).await;
}

// --- Gestione dei comandi su una connessione stabilita ---
#[instrument(skip(stream, etcd), fields(device_id = %device_id))]
async fn handle_commands(mut stream: TlsStream<TcpStream>, device_id: String, etcd: &mut Client) {
    info!("In attesa di comandi...");
    let mut reader = BufStream::new(&mut stream);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                info!("Connessione chiusa dal client.");
                break;
            }
            Ok(_) => {
                let command = line.trim();
                info!(%command, "Comando ricevuto.");
                let response = match serde_json::from_str::<CommandRequest>(command) {
                    Ok(req) if req.command == "REGISTER" => handle_registration(device_id.clone(), etcd).await,
                    Ok(req) if req.command == "HEARTBEAT" => handle_heartbeat(device_id.clone(), etcd).await,
                    Ok(req) => {
                        warn!(unsupported_command = %req.command, "Comando non supportato.");
                        CommandResponse { status: "error".to_string(), message: "Comando non supportato".to_string() }
                    }
                    Err(e) => {
                        warn!(error = %e, raw_command = command, "Comando JSON non valido.");
                        CommandResponse { status: "error".to_string(), message: "Comando JSON non valido".to_string() }
                    },
                };
                let response_json = serde_json::to_string(&response).unwrap() + "\n";
                if let Err(e) = reader.get_mut().write_all(response_json.as_bytes()).await {
                    error!(error = %e, "Errore di scrittura risposta.");
                    break;
                }
                reader.get_mut().flush().await.ok();
                info!(status = %response.status, "Risposta inviata.");
            }
            Err(e) => {
                error!(error = %e, "Errore di lettura, chiusura connessione.");
                break;
            }
        }
    }
}

// --- Gestione specifica dei comandi (con logging) ---
#[instrument(skip(etcd), fields(device_id = %device_id))]
async fn handle_registration(device_id: String, etcd: &mut Client) -> CommandResponse {
    let key = format!("devices/{}", device_id);
    info!("Processo di registrazione...");
    
    let get_resp = match etcd.get(key.clone(), None).await {
        Ok(resp) => resp,
        Err(e) => {
             error!(error = %e, "Errore etcd in lettura.");
             return CommandResponse { status: "error".to_string(), message: "Errore interno del server.".to_string() };
        }
    };

    if !get_resp.kvs().is_empty() {
        info!("Dispositivo già registrato.");
        return CommandResponse { status: "ok".to_string(), message: "Dispositivo già registrato.".to_string() };
    }

    let now = Utc::now();
    let device_info = DeviceInfo { device_id: device_id.clone(), status: "registered".to_string(), first_seen: now, last_seen: now };
    let value = serde_json::to_string(&device_info).unwrap();
    
    match etcd.put(key, value, None).await {
        Ok(_) => {
            info!("Dispositivo registrato con successo in etcd.");
            CommandResponse { status: "ok".to_string(), message: "Registrazione completata con successo.".to_string() }
        },
        Err(e) => {
            error!(error = %e, "Errore etcd in scrittura.");
            CommandResponse { status: "error".to_string(), message: "Errore interno del server.".to_string() }
        }
    }
}

#[instrument(skip(etcd), fields(device_id = %device_id))]
async fn handle_heartbeat(device_id: String, etcd: &mut Client) -> CommandResponse {
    let key = format!("devices/{}", device_id);
    
    let get_resp = match etcd.get(key.clone(), None).await {
        Ok(resp) => resp,
        Err(e) => {
            error!(error = %e, "Errore etcd in lettura durante heartbeat.");
            return CommandResponse { status: "error".to_string(), message: "Errore interno.".to_string() };
        }
    };

    if let Some(kv) = get_resp.kvs().first() {
        let mut device_info: DeviceInfo = serde_json::from_slice(kv.value()).unwrap();
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