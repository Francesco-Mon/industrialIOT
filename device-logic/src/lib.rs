use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
pub use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, Certificate, ClientConfig, PrivateKey, RootCertStore};
use tokio_rustls::TlsConnector;
use openssl::{pkey::{PKey, Private}, rsa::Rsa, x509::{X509NameBuilder, X509ReqBuilder}, hash::MessageDigest};

const CA_SERVER_URL: &str = "http://localhost:8000/sign-csr";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CommandRequest { command: String }
#[derive(Serialize, Deserialize, Debug, Clone)]
struct CommandResponse { status: String, message: String }
#[derive(Serialize)]
struct SignRequest<'a> { csr_pem: &'a str }

pub async fn run_device_workflow(key_path: &Path, cert_path: &Path) -> Result<()> {
    let (key_pair, client_certs) = get_or_create_identity(key_path, cert_path).await?;
    let client_key = PrivateKey(key_pair.private_key_to_der()?);
    let mut root_store = RootCertStore::empty();
    let ca_pem_bytes = fs::read("../certs/ca.crt")?;
    let ca_certs: Vec<Certificate> = rustls_pemfile::certs(&mut &*ca_pem_bytes)?.into_iter().map(Certificate).collect();
    root_store.add(ca_certs.first().unwrap())?;
    
    let config = ClientConfig::builder().with_safe_defaults().with_root_certificates(root_store).with_client_auth_cert(client_certs, client_key)?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_addr = "localhost:8443";
    let server_name: rustls::ServerName = "localhost".try_into().unwrap();
    
    println!("\n[+] Connessione a Registration Server: {}", server_addr);
    let tcp_stream = TcpStream::connect(server_addr).await?;
    let mut stream = connector.connect(server_name, tcp_stream).await?;
    println!("[+] Connessione TLS stabilita con successo.");
    
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
        println!("[{}] Heartbeat inviato.", chrono::Utc::now().format("%H:%M:%S"));

        match stream.read_u32().await {
            Ok(len) => {
                let mut buffer = vec![0; len as usize];
                if stream.read_exact(&mut buffer).await.is_err() { 
                    println!("Impossibile leggere corpo della risposta.");
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

async fn get_or_create_identity(key_path: &Path, cert_path: &Path) -> Result<(PKey<Private>, Vec<Certificate>)> {
    if key_path.exists() && cert_path.exists() {
        println!("[+] Identità trovata su disco ({:?}), caricamento...", key_path);
        let key_pem = fs::read(key_path)?;
        let cert_pem = fs::read(cert_path)?;
        let key_pair = PKey::private_key_from_pem(&key_pem)?;
        let certs = rustls_pemfile::certs(&mut &*cert_pem)?.into_iter().map(Certificate).collect();
        return Ok((key_pair, certs));
    }

    println!("[+] Nessuna identità in {:?}. Avvio provisioning...", key_path.parent().unwrap());
    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&key_pair)?;
    let mut name_builder = X509NameBuilder::new()?;
    let device_id = format!("device-{}", rand::random::<u32>());
    name_builder.append_entry_by_text("CN", &device_id)?;
    req_builder.set_subject_name(&name_builder.build())?;
    req_builder.sign(&key_pair, MessageDigest::sha256())?;
    let csr_pem = String::from_utf8(req_builder.build().to_pem()?)?;
    let client = reqwest::Client::new();
    let res = client.post(CA_SERVER_URL).json(&SignRequest { csr_pem: &csr_pem }).send().await?;
    if !res.status().is_success() {
        let status = res.status();
        let error_body = res.text().await.unwrap_or_else(|_| "Nessun dettaglio".into());
        anyhow::bail!("CA Server Error: {} - {}", status, error_body);
    }
    let signed_cert_pem = res.text().await?;
    fs::write(key_path, key_pair.private_key_to_pem_pkcs8()?)?;
    fs::write(cert_path, &signed_cert_pem)?;
    println!("[+] Identità per '{}' salvata in {:?}.", device_id, key_path.parent().unwrap());
    let certs = rustls_pemfile::certs(&mut signed_cert_pem.as_bytes())?.into_iter().map(Certificate).collect();
    Ok((key_pair, certs))
}