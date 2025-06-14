use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, Certificate, ClientConfig, PrivateKey, RootCertStore};
use tokio_rustls::TlsConnector;
use serde::{Deserialize, Serialize};
use chrono;
use rustls_pemfile::{certs, pkcs8_private_keys};

#[derive(Serialize, Deserialize, Debug)]
struct CommandRequest {
    command: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CommandResponse {
    status: String,
    message: String,
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
    let mut root_cert_store = RootCertStore::empty();
    let ca_certs = load_certs(Path::new("../certs/ca.crt"))?;
    for cert in ca_certs {
        root_cert_store.add(&cert).unwrap();
    }
    let client_certs = load_certs(Path::new("../certs/client.crt"))?;
    let client_key = load_private_key(Path::new("../certs/client.key"))?;
    let config = ClientConfig::builder().with_safe_defaults().with_root_certificates(root_cert_store).with_client_auth_cert(client_certs, client_key).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let connector = TlsConnector::from(Arc::new(config));
    
    let server_addr = "localhost:8443";
    let server_name: rustls::ServerName = "localhost".try_into().expect("invalid DNS name");

    println!("Tentativo di connessione a {}", server_addr);
    let tcp_stream = TcpStream::connect(server_addr).await?;
    let tls_stream = connector.connect(server_name, tcp_stream).await?;
    println!("Connessione TLS stabilita con successo.");

    let mut stream = TokioBufReader::new(tls_stream);

    println!("\n--- Fase 1: Registrazione ---");
    let register_cmd = CommandRequest { command: "REGISTER".to_string() };
    let json_cmd = serde_json::to_string(&register_cmd)? + "\n";
    
    stream.write_all(json_cmd.as_bytes()).await?;
    stream.flush().await?;
    
    let mut response_line = String::new();
    stream.read_line(&mut response_line).await?;
    println!("Risposta del server: {}", response_line.trim());

    println!("\n--- Fase 2: Invio Heartbeat ---");
    loop {
        let heartbeat_cmd = CommandRequest { command: "HEARTBEAT".to_string() };
        let json_cmd = serde_json::to_string(&heartbeat_cmd)? + "\n";

        if let Err(e) = stream.write_all(json_cmd.as_bytes()).await {
            eprintln!("Errore invio heartbeat: {}. Uscita.", e);
            break;
        }
        stream.flush().await?;
        println!("[{}] Heartbeat inviato.", chrono::Utc::now().format("%H:%M:%S"));

        response_line.clear();
        match stream.read_line(&mut response_line).await {
            Ok(0) | Err(_) => {
                println!("Connessione persa con il server. Uscita.");
                break;
            }
            Ok(_) => {
                println!("[{}] Risposta: {}", chrono::Utc::now().format("%H:%M:%S"), response_line.trim());
            }
        }
        
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    }
    
    Ok(())
}