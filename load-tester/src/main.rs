use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, Certificate, ClientConfig, PrivateKey, RootCertStore};
use tokio_rustls::TlsConnector;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rustls_pemfile::{certs, pkcs8_private_keys};

// Le struct di comunicazione
#[derive(Serialize, Deserialize, Debug, Clone)]
struct CommandRequest { command: String }
#[derive(Serialize, Deserialize, Debug, Clone)]
struct CommandResponse { status: String, message: String }

// Funzione completa per caricare i certificati
fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    let mut cert_file = BufReader::new(std::fs::File::open(path)?);
    certs(&mut cert_file)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

// Funzione completa per caricare la chiave privata
fn load_private_key(path: &Path) -> io::Result<PrivateKey> {
    let mut key_file = BufReader::new(std::fs::File::open(path)?);
    pkcs8_private_keys(&mut key_file)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid private key"))
        .map(|mut keys| PrivateKey(keys.remove(0)))
}

// Logica per un singolo client simulato
async fn run_single_client(device_id: String, root_store: Arc<RootCertStore>) {
    let cert_path = PathBuf::from(format!("../certs/{}.crt", device_id));
    let key_path = PathBuf::from(format!("../certs/{}.key", device_id));
    
    let client_certs = match load_certs(&cert_path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("[{}] Errore: certificato non trovato. Hai eseguito lo script 'generate_clients.sh'?", device_id);
            return;
        }
    };
    let client_key = match load_private_key(&key_path) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("[{}] Errore: chiave privata non trovata.", device_id);
            return;
        }
    };

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store.clone())
        .with_client_auth_cert(client_certs, client_key)
        .unwrap();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name: rustls::ServerName = "localhost".try_into().unwrap();

    let tcp_stream = match TcpStream::connect("localhost:8443").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[{}] Errore connessione TCP: {}", device_id, e);
            return;
        }
    };
    
    let mut stream = match connector.connect(server_name, tcp_stream).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[{}] Errore handshake TLS: {}", device_id, e);
            return;
        }
    };

    // Registrazione
    let register_cmd = CommandRequest { command: "REGISTER".to_string() };
    let cmd_bytes = bincode::serialize(&register_cmd).unwrap();
    
    if stream.write_u32(cmd_bytes.len() as u32).await.is_err() { return; }
    if stream.write_all(&cmd_bytes).await.is_err() { return; }
    if stream.flush().await.is_err() { return; }
    
    if let Ok(len) = stream.read_u32().await {
        let mut buffer = vec![0; len as usize];
        if stream.read_exact(&mut buffer).await.is_err() { return; }
    } else {
        return;
    }
    
    println!("[{}] Registrato. Inizio heartbeat.", device_id);
    
    // Loop di Heartbeat
    loop {
        let heartbeat_cmd = CommandRequest { command: "HEARTBEAT".to_string() };
        let cmd_bytes = bincode::serialize(&heartbeat_cmd).unwrap();
        
        if stream.write_u32(cmd_bytes.len() as u32).await.is_err() { break; }
        if stream.write_all(&cmd_bytes).await.is_err() { break; }
        if stream.flush().await.is_err() { break; }
        
        if let Ok(len) = stream.read_u32().await {
            let mut buffer = vec![0; len as usize];
            if stream.read_exact(&mut buffer).await.is_err() { break; }
        } else {
            break;
        }
        
        tokio::time::sleep(Duration::from_secs(30)).await;
    }

    eprintln!("[{}] Connessione terminata.", device_id);
}

// --- Funzione Principale del Load Tester ---
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Uso: {} <numero_client>", args[0]);
        return;
    }
    let num_clients: usize = args[1].parse().expect("Numero di client non valido.");

    println!("Avvio di {} client concorrenti...", num_clients);

    let ca_certs = load_certs(Path::new("../certs/ca.crt")).unwrap();
    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(&cert).unwrap();
    }
    let root_store = Arc::new(root_store);

    let mut tasks = Vec::new();
    for i in 1..=num_clients {
        let device_id = format!("device-{:04}", i);
        let root_store_clone = root_store.clone();
        let task = tokio::spawn(run_single_client(device_id, root_store_clone));
        tasks.push(task);
        // Aggiungi un piccolo ritardo per non sovraccaricare il server istantaneamente
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    for task in tasks {
        let _ = task.await;
    }

    println!("Test di carico completato.");
}