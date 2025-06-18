# Secure Device Registration System with Rust and etcd

Questo progetto implementa un'infrastruttura sicura, robusta e scalabile per la registrazione e l'autenticazione di dispositivi, ideale per scenari IoT o di sistemi distribuiti. La soluzione, scritta interamente in **Rust**, si basa su un modello di **autenticazione reciproca (mTLS)** e utilizza un **servizio di Certificate Authority (CA) online** per il provisioning dinamico delle identità.

L'architettura è completamente containerizzata con **Docker** e orchestrata tramite **Docker Compose**, garantendo riproducibilità e un ambiente di deployment pulito.

## Architettura del Sistema

Il sistema è basato su un'architettura a microservizi, composta da quattro componenti principali che comunicano su una rete Docker privata:

1.  **CA Server**: Un microservizio Rust che agisce come Certificate Authority. La sua unica responsabilità è ricevere Certificate Signing Requests (CSR) dai nuovi dispositivi, firmarle con la chiave privata della CA, e registrare il certificato emesso in `etcd`.
2.  **Registration Server**: Il gateway principale del sistema. È un server asincrono Rust che gestisce le connessioni TLS dei dispositivi. Valida l'identità di ogni dispositivo tramite mTLS, verifica che il suo certificato sia autorizzato (controllando su `etcd`), e gestisce i workflow di registrazione e heartbeat.
3.  **Client (Device)**: Un'applicazione Rust che simula un dispositivo IoT. Implementa il workflow di provisioning dinamico: al primo avvio, genera una coppia di chiavi, contatta la CA per ottenere un certificato, e lo salva localmente per le sessioni future.
4.  **etcd**: Un data store chiave-valore distribuito che funge da "source of truth" per il sistema. Memorizza sia i certificati emessi dalla CA sia i record di stato (metadati, attività) dei dispositivi gestiti dal Registration Server.

 
*(Nota: Si raccomanda di sostituire questo link con un diagramma reale creato con strumenti come [diagrams.net](http://diagrams.net))*

## Workflow di Provisioning Dinamico

Il cuore del sistema è il suo flusso di onboarding "zero-touch":

1.  Un nuovo dispositivo (client) si avvia per la prima volta. Non ha un'identità.
2.  Genera localmente una coppia di chiavi crittografiche (RSA 2048 bit).
3.  Crea una Certificate Signing Request (CSR) che contiene la sua nuova chiave pubblica e un Common Name (CN) univoco.
4.  Invia la CSR tramite una richiesta HTTP POST al **CA Server**.
5.  Il **CA Server** valida la CSR, la firma con la sua chiave privata, e genera un certificato X.509 valido.
6.  Il **CA Server** salva una copia del certificato emesso in `etcd`. Questo serve come registro di tutti i dispositivi autorizzati.
7.  Il **CA Server** restituisce il certificato firmato al dispositivo.
8.  Il dispositivo salva permanentemente la sua chiave privata e il certificato ricevuto.
9.  Da questo momento in poi, il dispositivo è "provisionato" e userà questa identità per tutte le future comunicazioni con il **Registration Server** tramite mTLS.

## Funzionalità Chiave

- ✅ **Sicurezza a più livelli**: Autenticazione mTLS, CA online per il controllo delle identità, e isolamento dei servizi tramite rete Docker.
- ✅ **Provisioning Dinamico**: I dispositivi si auto-configurano al primo avvio, eliminando la necessità di distribuire le chiavi manualmente.
- ✅ **Protocollo Binario Efficiente**: La comunicazione tra client e server di registrazione avviene tramite un protocollo TCP custom basato su messaggi con lunghezza prefissata e serializzazione `bincode`, ideale per ambienti con banda limitata.
- ✅ **Resilienza e Fault Tolerance**: Il server è progettato per gestire la disconnessione e riconnessione a `etcd` e utilizza transazioni atomiche per operazioni critiche, garantendo la consistenza dei dati.
- ✅ **Deployment Riproducibile**: L'intera architettura viene avviata con un singolo comando (`docker-compose up`), garantendo un ambiente di sviluppo e test consistente.
- ✅ **Monitoring**: Ogni servizio espone un endpoint `/health` e produce log strutturati in formato JSON per una facile integrazione con sistemi di observability.

## Tecnologie Utilizzate

- **Linguaggio**: Rust (Edizione 2021)
- **Networking Asincrono**: Tokio, `rustls`
- **Framework Web (CA Server)**: Axum
- **Crittografia**: `openssl` per la gestione di chiavi e certificati
- **Data Store**: `etcd` v3.5
- **Protocollo**: Custom TCP binario con `bincode`
- **Deployment**: Docker, Docker Compose
- **Testing**: Test di integrazione nativi con `testcontainers-rs` (implementati nella cronologia del progetto, poi sostituiti con unit test più stabili a causa di instabilità delle dipendenze).

## Guida all'Esecuzione e Demo

### Prerequisiti
-   **Docker** e **Docker Compose** installati e in esecuzione.
-   **Rust** e **Cargo** installati.

### 1. Avvio dell'Infrastruttura
Questo comando costruisce le immagini Docker per i server e avvia l'intero stack in background.

```bash
# Dalla cartella radice del progetto
docker-compose up --build -d
```
Attendere circa 30-40 secondi, poi verificare che tutti i servizi siano in salute:
```bash
docker ps
# L'output dovrebbe mostrare i 3 container con STATUS (healthy)
```

### 2. Esecuzione del Client (Provisioning e Operatività)
Il client singolo dimostra il workflow completo, inclusa la persistenza dell'identità.

**Prima Esecuzione (Provisioning):**
```bash
# Pulisci eventuali identità precedenti
rm -f registration-client/device.key registration-client/device.crt

# Esegui il client
cd registration-client
cargo run
```
*Output atteso*: Vedrai i messaggi che descrivono la creazione di una nuova identità e la comunicazione con la CA, seguita dalla registrazione e dagli heartbeat.

**Seconda Esecuzione (Riutilizzo):**
```bash
# Esegui di nuovo il client
cargo run
```
*Output atteso*: Vedrai il messaggio "Identità trovata su disco, caricamento in corso...", seguito direttamente dalla connessione al server.

## Testing

### Test di Carico
Per simulare 1000 dispositivi indipendenti che eseguono il provisioning e si connettono contemporaneamente:

```bash
# Nel terminale del test, aumenta il limite di file aperti (macOS/Linux)
ulimit -n 4096

# Naviga nella cartella del load-tester
cd load-tester

# Esegui il test in modalità ottimizzata
cargo run --release 1000
```
Questo test dimostra la capacità dell'architettura di gestire un carico elevato di connessioni concorrenti.

## Scelte di Design e Sviluppi Futuri

- **Architettura a Microservizi**: La separazione della logica in tre servizi distinti (`ca-server`, `registration-server`, `etcd`) aumenta la manutenibilità, la scalabilità e la sicurezza, seguendo i principi del "separation of concerns".
- **Sviluppi Futuri**:
  - **Deployment su Kubernetes**: Per ottenere un'alta disponibilità e una scalabilità orizzontale reali, il passo successivo sarebbe deployare lo stack su un cluster Kubernetes, gestendo le repliche dei server con un `Deployment` e l'esposizione con un `Service` e un `Ingress`.
  - **CI/CD Pipeline**: Automatizzare i test e la build delle immagini Docker tramite un workflow di GitHub Actions per garantire la qualità del codice e velocizzare i rilasci.
  - **Miglioramento della Sicurezza della CA**: In produzione, la chiave privata della CA non risiederebbe su un filesystem, ma verrebbe protetta da un Hardware Security Module (HSM) o un servizio cloud come AWS KMS.
