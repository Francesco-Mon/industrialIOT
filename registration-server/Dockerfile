# --- STAGE 1: Build ---
# Usiamo una versione di Rust compatibile (1.81 o più recente).
FROM rust:1.81-slim AS builder

# MODIFICA: Installiamo le dipendenze di sistema necessarie per la compilazione.
# `protobuf-compiler` è richiesto da `etcd-client` (tramite `prost-build`) per compilare i file .proto.
# `pkg-config` e `libssl-dev` sono spesso richiesti per crate che usano crittografia nativa.
RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Impostiamo la directory di lavoro all'interno del container.
WORKDIR /usr/src/app

# Copiamo i file di dipendenze per sfruttare la cache di Docker.
COPY registration-server/Cargo.toml registration-server/Cargo.lock ./

# Creiamo un progetto fittizio solo per scaricare e compilare le dipendenze.
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# Ora copiamo il nostro codice sorgente reale.
COPY registration-server/src ./src

# Compiliamo il nostro progetto. Le dipendenze sono già nella cache, quindi questo sarà veloce.
RUN cargo build --release

# --- STAGE 2: Final ---
# Partiamo da un'immagine di base molto leggera per l'esecuzione.
FROM debian:bookworm-slim AS final

# Installiamo i certificati CA del sistema operativo, una buona pratica per le connessioni in uscita.
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copiamo solo il file eseguibile compilato dallo stage 'builder'.
COPY --from=builder /usr/src/app/target/release/registration-server /usr/local/bin/

# Copiamo i nostri certificati TLS nell'immagine.
COPY certs /certs

# Esponiamo la porta 8443, su cui il nostro server ascolta.
EXPOSE 8443

# Comando da eseguire quando il container viene avviato.
CMD ["/usr/local/bin/registration-server"]