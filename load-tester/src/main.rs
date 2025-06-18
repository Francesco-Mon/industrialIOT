use anyhow::Result;
use std::env;
use std::time::Duration;
use device_logic::run_device_workflow;

async fn run_single_device_instance(id: usize) {
    let temp_dir = env::temp_dir().join(format!("device-test-{}", id));
    if let Err(e) = std::fs::create_dir_all(&temp_dir) {
        eprintln!("[Client {}] Impossibile creare directory temporanea: {:?}", id, e);
        return;
    }

    let key_path = temp_dir.join("device.key");
    let cert_path = temp_dir.join("device.crt");
    
    println!("[Client {}] Avvio workflow in dir: {:?}", id, temp_dir);

    if let Err(e) = run_device_workflow(&key_path, &cert_path).await {
        eprintln!("[Client {}] Errore durante l'esecuzione: {:?}", id, e);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        anyhow::bail!("Uso: {} <numero_client>", args[0]);
    }
    let num_clients: usize = args[1].parse()?;
    println!("Avvio del test di carico con {} client indipendenti...", num_clients);

    let mut tasks = Vec::new();
    for i in 1..=num_clients {
        let task = tokio::spawn(run_single_device_instance(i));
        tasks.push(task);

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    for task in tasks {
        task.await?;
    }

    println!("\nTest di carico completato (o interrotto).");
    Ok(())
}