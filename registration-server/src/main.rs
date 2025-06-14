use std::env; // <-- Import per le variabili d'ambiente
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use etcd_client::Client;
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::*;

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

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    let mut cert_file = BufReader::new(File::open(path)?);
    certs(&mut cert_file).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert")).map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_private_key(path: &Path) -> io::Result<PrivateKey> {
    let mut key_file = BufReader::new(File::open(path)?);
    pkcs8_private_keys(&mut key_file).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid private key")).map(|mut keys| PrivateKey(keys.remove(0)))
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let addr: SocketAddr = "0.0.0.0:8443".parse().unwrap();
    let server_certs = load_certs(Path::new("./certs/server.crt"))?;
    let server_key = load_private_key(Path::new("./certs/server.key"))?;
    let client_ca_cert = load_certs(Path::new("./certs/ca.crt"))?;
    
    let mut client_auth_roots = rustls::RootCertStore::empty();
    for cert in client_ca_cert {
        client_auth_roots.add(&cert).unwrap();
    }
    
    let client_cert_verifier = rustls::server::AllowAnyAuthenticatedClient::new(client_auth_roots);
    let tls_config = rustls::ServerConfig::builder().with_safe_defaults().with_client_cert_verifier(Arc::new(client_cert_verifier)).with_single_cert(server_certs, server_key).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // --- MODIFICA CHIAVE: Lettura dell'endpoint di etcd dall'ambiente ---
    println!("Connessione a etcd...");
    let etcd_endpoint = env::var("ETCD_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:2379".to_string());
    println!("Usando endpoint etcd: {}", etcd_endpoint);
    let etcd_client = Client::connect([etcd_endpoint], None).await.expect("Impossibile connettersi a etcd.");
    println!("Connesso a etcd con successo.");
    // --- FINE MODIFICA ---

    let listener = TcpListener::bind(&addr).await?;
    println!("Server in ascolto su https://{}", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        println!("\nNuova connessione da: {}", peer_addr);
        let acceptor = acceptor.clone();
        let mut etcd_client_clone = etcd_client.clone();

        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[{}] Errore handshake TLS: {}", peer_addr, e);
                    return;
                }
            };
            
            let (_, server_conn) = stream.get_ref();
            let device_id = match server_conn.peer_certificates() {
                Some(certs) if !certs.is_empty() => match parse_x509_certificate(&certs[0].0) {
                    Ok((_, cert)) => cert.subject().iter_common_name().next().map(|cn| cn.as_str().unwrap_or("unknown-device").to_string()).unwrap_or_else(|| "unknown-device-no-cn".to_string()),
                    Err(_) => "unknown-device-parsing-failed".to_string(),
                },
                _ => "unknown-device-no-cert".to_string(),
            };
            
            println!("[{}] Handshake TLS completato", device_id);
            if device_id.starts_with("unknown-device") {
                eprintln!("[{}] Impossibile identificare il dispositivo.", device_id);
                return;
            }
            
            handle_connection(stream, device_id, &mut etcd_client_clone).await;
        });
    }
}

async fn handle_connection(mut stream: TlsStream<TcpStream>, device_id: String, etcd: &mut Client) {
    println!("[{}] In attesa di comandi...", &device_id);
    let mut reader = BufStream::new(&mut stream);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                println!("[{}] Connessione chiusa.", &device_id);
                break;
            }
            Ok(_) => {
                println!("[{}] Comando ricevuto: {}", &device_id, line.trim());
                let response = match serde_json::from_str::<CommandRequest>(&line) {
                    Ok(req) if req.command == "REGISTER" => handle_registration(device_id.clone(), etcd).await,
                    Ok(req) if req.command == "HEARTBEAT" => handle_heartbeat(device_id.clone(), etcd).await,
                    Ok(req) => {
                        eprintln!("[{}] Comando non supportato: {}", &device_id, req.command);
                        CommandResponse { status: "error".to_string(), message: "Comando non supportato".to_string() }
                    }
                    Err(_) => CommandResponse { status: "error".to_string(), message: "Comando JSON non valido".to_string() },
                };
                let response_json = serde_json::to_string(&response).unwrap() + "\n";
                if let Err(e) = reader.get_mut().write_all(response_json.as_bytes()).await {
                    eprintln!("[{}] Errore di scrittura: {}", &device_id, e);
                    break;
                }
                reader.get_mut().flush().await.ok();
                println!("[{}] Risposta inviata: status='{}'", &device_id, response.status);
            }
            Err(e) => {
                eprintln!("[{}] Errore di lettura: {}. Chiusura connessione.", &device_id, e);
                break;
            }
        }
    }
}

async fn handle_registration(device_id: String, etcd: &mut Client) -> CommandResponse {
    let key = format!("devices/{}", device_id);
    println!("[{}] Processo di registrazione...", &device_id);
    let get_resp = match etcd.get(key.clone(), None).await {
        Ok(resp) => resp,
        Err(e) => {
             eprintln!("[{}] Errore etcd (lettura): {}", &device_id, e);
             return CommandResponse { status: "error".to_string(), message: "Errore interno del server.".to_string() };
        }
    };
    if !get_resp.kvs().is_empty() {
        println!("[{}] Dispositivo già registrato.", &device_id);
        return CommandResponse { status: "ok".to_string(), message: "Dispositivo già registrato.".to_string() };
    }
    let now = Utc::now();
    let device_info = DeviceInfo { device_id: device_id.clone(), status: "registered".to_string(), first_seen: now, last_seen: now };
    let value = serde_json::to_string(&device_info).unwrap();
    match etcd.put(key, value, None).await {
        Ok(_) => {
            println!("[{}] Registrato con successo.", &device_id);
            CommandResponse { status: "ok".to_string(), message: "Registrazione completata con successo.".to_string() }
        },
        Err(e) => {
            eprintln!("[{}] Errore etcd (scrittura): {}", &device_id, e);
            CommandResponse { status: "error".to_string(), message: "Errore interno del server.".to_string() }
        }
    }
}

async fn handle_heartbeat(device_id: String, etcd: &mut Client) -> CommandResponse {
    let key = format!("devices/{}", device_id);
    let get_resp = match etcd.get(key.clone(), None).await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("[{}] Errore heartbeat (lettura etcd): {}", &device_id, e);
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
                eprintln!("[{}] Errore heartbeat (scrittura etcd): {}", &device_id, e);
                CommandResponse { status: "error".to_string(), message: "Errore interno.".to_string() }
            }
        }
    } else {
        CommandResponse { status: "error".to_string(), message: "Dispositivo non registrato.".to_string() }
    }
}