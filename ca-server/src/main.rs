use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use etcd_client::Client;
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{X509, X509Name, X509Req},
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, instrument};
use tracing_subscriber::{prelude::*, EnvFilter};

#[derive(Deserialize)]
struct SignRequest {
    csr_pem: String,
}

struct AppState {
    ca_cert: X509,
    ca_pkey: PKey<Private>,
    etcd_client: Client,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry().with(tracing_subscriber::fmt::layer().json()).with(EnvFilter::from_default_env()).init();

    info!("Caricamento della CA da /certs/...");
    let ca_pkey_pem = std::fs::read_to_string("/certs/ca.key")?;
    let ca_pkey = PKey::private_key_from_pem(ca_pkey_pem.as_bytes())?;
    let ca_cert_pem = std::fs::read_to_string("/certs/ca.crt")?;
    let ca_cert = X509::from_pem(ca_cert_pem.as_bytes())?;

    let etcd_endpoint = std::env::var("ETCD_ENDPOINT").unwrap_or_else(|_| "http://localhost:2379".to_string());
    info!(endpoint = %etcd_endpoint, "Connessione a etcd...");
    let etcd_client = Client::connect([etcd_endpoint], None).await?;
    info!("Connesso a etcd con successo.");

    let app_state = Arc::new(AppState { ca_cert, ca_pkey, etcd_client });

    let app = Router::new()
        .route("/sign-csr", post(sign_csr_handler))
        .route("/health", get(|| async { "OK" }));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await?;
    info!("CA Server in ascolto su http://0.0.0.0:8000");
    axum::serve(listener, app.with_state(app_state)).await?;

    Ok(())
}

fn create_serial_number() -> Result<BigNum, ErrorStack> {
    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    Ok(serial)
}

#[instrument(skip_all)]
async fn sign_csr_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SignRequest>,
) -> Result<String, (StatusCode, String)> {
    info!("Ricevuta richiesta di firma CSR.");
    
    let req = X509Req::from_pem(payload.csr_pem.as_bytes())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("CSR PEM non valido: {}", e)))?;
        
    let subject_name: X509Name = req.subject_name().to_owned().unwrap();
    let device_id = subject_name.entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Common Name (CN) non trovato nella CSR.".to_string()))?;
        
    info!(%device_id, "Inizio processo di firma per il dispositivo.");

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&subject_name).unwrap();
    builder.set_issuer_name(state.ca_cert.subject_name()).unwrap();
    builder.set_pubkey(&req.public_key().unwrap()).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    builder.set_serial_number(&create_serial_number().unwrap().to_asn1_integer().unwrap()).unwrap();
    
    builder.sign(&state.ca_pkey, MessageDigest::sha256()).unwrap();
    
    let signed_cert = builder.build();
    let signed_cert_pem = String::from_utf8(signed_cert.to_pem().unwrap()).unwrap();

    info!(%device_id, "Salvataggio del certificato firmato su etcd.");
    let key = format!("devices/certificates/{}", device_id);
    let mut etcd_client = state.etcd_client.clone();
    
    if let Err(e) = etcd_client.put(key, signed_cert_pem.clone(), None).await {
        error!(error = %e, "Fallito salvataggio su etcd per {}", device_id);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Errore di storage interno.".to_string()));
    }

    info!(%device_id, "Certificato firmato e salvato con successo.");
    Ok(signed_cert_pem)
}