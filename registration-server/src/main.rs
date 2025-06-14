use std::env;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use axum::{routing::get, Router};
use etcd_client::Client;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, instrument, warn};
use tracing_subscriber::{prelude::*, EnvFilter};
use x509_parser::prelude::*;

// Importa la logica di business e i tipi dalla nostra libreria
use registration_server::{handle_heartbeat, handle_registration, CommandRequest, CommandResponse};

// --- Funzioni Helper TLS ---
fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    let mut cert_file = BufReader::new(File::open(path)?);
    certs(&mut cert_file).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert")).map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_private_key(path: &Path) -> io::Result<PrivateKey> {
    let mut key_file = BufReader::new(File::open(path)?);
    pkcs8_private_keys(&mut key_file).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid private key")).map(|mut keys| PrivateKey(keys.remove(0)))
}

// --- Funzione Principale ---
#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::registry().with(tracing_subscriber::fmt::layer().json()).with(EnvFilter::from_default_env()).init();
    info!("Avvio del sistema di registrazione dispositivi.");
    let health_handle = tokio::spawn(health_check_server());
    let server_handle = tokio::spawn(main_server());
    tokio::select! {
        res = health_handle => { error!(result = ?res, "Il server di Health Check è terminato inaspettatamente."); }
        res = server_handle => { error!(result = ?res, "Il server principale è terminato inaspettatamente."); }
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

    let etcd_endpoint = env::var("ETCD_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:2379".to_string());
    info!(endpoint = %etcd_endpoint, "Connessione a etcd...");
    let etcd_client = Client::connect([etcd_endpoint], None).await.expect("Connessione a etcd fallita.");
    info!("Connesso a etcd con successo.");

    let listener = TcpListener::bind(&addr).await.expect("Binding della porta principale fallito.");
    info!(address = %addr, "Server principale in ascolto.");

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let acceptor = acceptor.clone();
                let etcd_client_clone = etcd_client.clone();
                tokio::spawn(handle_new_connection(stream, peer_addr, acceptor, etcd_client_clone));
            },
            Err(e) => {
                error!(error = %e, "Errore durante l'accettazione di una nuova connessione.");
            }
        }
    }
}

// --- Gestione di una singola nuova connessione ---
#[instrument(skip_all, fields(peer_addr = %peer_addr))]
async fn handle_new_connection(stream: TcpStream, peer_addr: SocketAddr, acceptor: TlsAcceptor, mut etcd_client: Client) {
    info!("Nuova connessione ricevuta.");

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
    info!("In attesa di comandi binari...");
    
    loop {
        // 1. Leggi i 4 byte della lunghezza del messaggio
        let len = match stream.read_u32().await {
            Ok(len) => len as usize,
            Err(_) => {
                info!("Connessione chiusa o errore di lettura lunghezza.");
                break;
            }
        };

        // Un semplice controllo di sicurezza per evitare messaggi enormi
        if len > 1024 * 1024 { // 1 MB
            error!(message_len = len, "Messaggio troppo grande, chiusura connessione.");
            break;
        }

        // 2. Leggi esattamente `len` byte per il messaggio
        let mut buffer = vec![0; len];
        if let Err(_) = stream.read_exact(&mut buffer).await {
            error!("Errore durante la lettura del corpo del messaggio.");
            break;
        }
        
        info!(bytes_read = len, "Comando binario ricevuto.");
        
        // 3. Deserializza il comando usando bincode
        let response = match bincode::deserialize::<CommandRequest>(&buffer) {
            Ok(req) if req.command == "REGISTER" => handle_registration(device_id.clone(), etcd).await,
            Ok(req) if req.command == "HEARTBEAT" => handle_heartbeat(device_id.clone(), etcd).await,
            Ok(req) => {
                warn!(unsupported_command = %req.command, "Comando non supportato.");
                CommandResponse { status: "error".to_string(), message: "Comando non supportato".to_string() }
            }
            Err(e) => {
                warn!(error = %e, "Comando binario non valido.");
                CommandResponse { status: "error".to_string(), message: "Comando binario non valido".to_string() }
            },
        };

        // 4. Serializza la risposta e inviala
        let response_bytes = bincode::serialize(&response).unwrap();
        // Prima invia la lunghezza...
        if stream.write_u32(response_bytes.len() as u32).await.is_err() {
            break;
        }
        // ...poi i dati.
        if stream.write_all(&response_bytes).await.is_err() {
            break;
        }
        info!(status = %response.status, "Risposta binaria inviata.");
    }
}