use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, Certificate, ClientConfig, PrivateKey, RootCertStore};
use tokio_rustls::TlsConnector;

// --- NUOVE DIPENDENZE OPENSSL ---
use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509NameBuilder, X509Req, X509ReqBuilder},
    hash::MessageDigest,
};


const KEY_PATH: &str = "device.key";
const CERT_PATH: &str = "device.crt";
const CA_SERVER_URL: &str = "http://localhost:8000/sign-csr";

// --- Struct di Comunicazione ---
#[derive(Serialize, Deserialize, Debug, Clone)]
struct CommandRequest { command: String }
#[derive(Serialize, Deserialize, Debug, Clone)]
struct CommandResponse { status: String, message: String }
#[derive(Serialize)]
struct SignRequest<'a> { csr_pem: &'a str }


// --- Logica di Identità con OpenSSL ---
async fn get_or_create_identity() -> Result<(PKey<Private>, Vec<Certificate>)> {
    if Path::new(KEY_PATH).exists() && Path::new(CERT_PATH).exists() {
        println!("[+] Identità trovata su disco, caricamento in corso...");
        let key_pem = fs::read(KEY_PATH)?;
        let cert_pem = fs::read(CERT_PATH)?;
        
        let key_pair = PKey::private_key_from_pem(&key_pem)?;
        let certs = rustls_pemfile::certs(&mut &*cert_pem)?
            .into_iter()
            .map(Certificate)
            .collect();
            
        return Ok((key_pair, certs));
    }

    println!("[+] Nessuna identità locale trovata. Avvio del processo di provisioning...");

    // 1. Genera una nuova coppia di chiavi RSA
    println!("  [1/4] Generazione nuova coppia di chiavi RSA (2048 bit)...");
    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;
    
    // 2. Crea una CSR (Certificate Signing Request)
    println!("  [2/4] Creazione della Richiesta di Firma del Certificato (CSR)...");
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&key_pair)?;

    let mut name_builder = X509NameBuilder::new()?;
    let device_id = format!("device-{}", rand::random::<u32>());
    name_builder.append_entry_by_text("CN", &device_id)?;
    let subject_name = name_builder.build();
    req_builder.set_subject_name(&subject_name)?;
    
    req_builder.sign(&key_pair, MessageDigest::sha256())?;
    let csr: X509Req = req_builder.build();
    let csr_pem = String::from_utf8(csr.to_pem()?)?;

    // 3. Invia la CSR al CA Server per la firma
    println!("  [3/4] Invio CSR al CA Server per {}", device_id);
    let client = reqwest::Client::new();
    let sign_request = SignRequest { csr_pem: &csr_pem };
    
    let res = client.post(CA_SERVER_URL).json(&sign_request).send().await?;
    
    if !res.status().is_success() {
        let status = res.status();
        let error_body = res.text().await.unwrap_or_else(|_| "Nessun dettaglio".into());
        anyhow::bail!("Il CA Server ha risposto con un errore: {} - {}", status, error_body);
    }
    
    let signed_cert_pem = res.text().await?;
    println!("  [4/4] Certificato ricevuto e firmato con successo!");

    // 4. Salva la chiave privata e il nuovo certificato su disco
    fs::write(KEY_PATH, key_pair.private_key_to_pem_pkcs8()?)?;
    fs::write(CERT_PATH, &signed_cert_pem)?;
    println!("[+] Identità per il dispositivo '{}' salvata localmente.", device_id);

    let certs = rustls_pemfile::certs(&mut signed_cert_pem.as_bytes())?
        .into_iter()
        .map(Certificate)
        .collect();

    Ok((key_pair, certs))
}


// --- Funzione Principale ---
#[tokio::main]
async fn main() -> Result<()> {
    // Ottiene o crea dinamicamente l'identità del dispositivo
    let (key_pair, client_certs) = get_or_create_identity().await?;
    let client_key = PrivateKey(key_pair.private_key_to_der()?);

    // Configura la connessione TLS, fidandosi della CA radice
    let mut root_store = RootCertStore::empty();
    let ca_pem_bytes = fs::read("../certs/ca.crt")?;
    let ca_certs: Vec<Certificate> = rustls_pemfile::certs(&mut &*ca_pem_bytes)?
        .into_iter()
        .map(Certificate)
        .collect();
    root_store.add(ca_certs.first().unwrap())?;

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)?;

    let connector = TlsConnector::from(Arc::new(config));
    let server_addr = "localhost:8443";
    let server_name: rustls::ServerName = "localhost".try_into().unwrap();

    println!("\n[+] Tentativo di connessione al Registration Server a {}", server_addr);
    let tcp_stream = TcpStream::connect(server_addr).await?;
    let mut stream = connector.connect(server_name, tcp_stream).await?;
    println!("[+] Connessione TLS stabilita con successo.");

    // --- Inizio del workflow di comunicazione binaria ---
    println!("\n--- Fase 1: Registrazione (binaria) ---");
    let register_cmd = CommandRequest { command: "REGISTER".to_string() };
    let cmd_bytes = bincode::serialize(&register_cmd).unwrap();
    stream.write_u32(cmd_bytes.len() as u32).await?;
    stream.write_all(&cmd_bytes).await?;
    stream.flush().await?;
    let len = stream.read_u32().await?;
    let mut buffer = vec![0; len as usize];
    stream.read_exact(&mut buffer).await?;
    let response: CommandResponse = bincode::deserialize(&buffer).unwrap();
    println!("Risposta del server: {:?}", response);

    println!("\n--- Fase 2: Invio Heartbeat (binario) ---");
    loop {
        let heartbeat_cmd = CommandRequest { command: "HEARTBEAT".to_string() };
        let cmd_bytes = bincode::serialize(&heartbeat_cmd).unwrap();
        if stream.write_u32(cmd_bytes.len() as u32).await.is_err() { break; }
        if stream.write_all(&cmd_bytes).await.is_err() { break; }
        stream.flush().await?;
        println!("[{}] Heartbeat binario inviato.", chrono::Utc::now().format("%H:%M:%S"));
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
        
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    
    Ok(())
}