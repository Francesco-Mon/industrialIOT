use device_logic::run_device_workflow;
use std::path::Path;

#[tokio::main]
async fn main() {
    println!("--- ESECUZIONE CLIENT SINGOLO ---");
    let key_path = Path::new("device.key");
    let cert_path = Path::new("device.crt");
    if let Err(e) = run_device_workflow(key_path, cert_path).await {
        eprintln!("Errore critico del client: {:?}", e);
    }
}