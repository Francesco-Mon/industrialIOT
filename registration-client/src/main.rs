use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, Certificate, ClientConfig, PrivateKey, RootCertStore};
use tokio_rustls::TlsConnector;
use serde::{Deserialize, Serialize};
use chrono;
use rustls_pemfile::{certs, pkcs8_private_keys};

// Importiamo le funzioni per leggere/scrivere interi e buffer, necessarie per il protocollo binario
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Le nostre struct rimangono le stesse, `serde` e `bincode` le gestiscono entrambe.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct CommandRequest {
    command: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CommandResponse {
    status: String,
    message: String,
}

// Le funzioni per caricare i certificati rimangono invariate.
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
    // --- Configurazione TLS e Connessione (invariata) ---
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
    // Ora `stream` non è più un BufReader, ma direttamente lo stream TLS.
    let mut stream = connector.connect(server_name, tcp_stream).await?;
    println!("Connessione TLS stabilita con successo.");


    // --- Fase 1: Registrazione (con protocollo binario) ---
    println!("\n--- Fase 1: Registrazione (binaria) ---");
    let register_cmd = CommandRequest { command: "REGISTER".to_string() };
    // Serializziamo il comando in un buffer di byte usando bincode
    let cmd_bytes = bincode::serialize(&register_cmd).unwrap();
    
    // 1. Invia la lunghezza del messaggio (4 byte, u32)
    stream.write_u32(cmd_bytes.len() as u32).await?;
    // 2. Invia i dati del messaggio
    stream.write_all(&cmd_bytes).await?;
    stream.flush().await?;
    
    // Leggi la risposta dal server
    // 1. Leggi la lunghezza della risposta
    let len = stream.read_u32().await?;
    // 2. Leggi esattamente `len` byte
    let mut buffer = vec![0; len as usize];
    stream.read_exact(&mut buffer).await?;
    // 3. Deserializza la risposta
    let response: CommandResponse = bincode::deserialize(&buffer).unwrap();
    println!("Risposta del server: {:?}", response);


    // --- Fase 2: Invio Heartbeat (con protocollo binario) ---
    println!("\n--- Fase 2: Invio Heartbeat (binario) ---");
    loop {
        let heartbeat_cmd = CommandRequest { command: "HEARTBEAT".to_string() };
        let cmd_bytes = bincode::serialize(&heartbeat_cmd).unwrap();

        // Invia comando binario (lunghezza + dati)
        if stream.write_u32(cmd_bytes.len() as u32).await.is_err() { break; }
        if stream.write_all(&cmd_bytes).await.is_err() { break; }
        stream.flush().await?;
        println!("[{}] Heartbeat binario inviato.", chrono::Utc::now().format("%H:%M:%S"));

        // Leggi risposta binaria (lunghezza + dati)
        match stream.read_u32().await {
            Ok(len) => {
                let mut buffer = vec![0; len as usize];
                if stream.read_exact(&mut buffer).await.is_err() { 
                    println!("Impossibile leggere il corpo della risposta.");
                    break; 
                }
                let response: CommandResponse = bincode::deserialize(&buffer).unwrap();
                println!("[{}] Risposta: {:?}", chrono::Utc::now().format("%H:%M:%S"), response);
            }
            Err(_) => {
                println!("Connessione persa con il server.");
                break;
            }
        }
        
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    }
    
    Ok(())
}