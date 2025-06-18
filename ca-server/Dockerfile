# Stage 1: Build
FROM rust:1.81-slim AS builder
WORKDIR /usr/src/app
# AGGIUNGIAMO le dipendenze per openssl-sys
RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev clang && rm -rf /var/lib/apt/lists/*
COPY ca-server/ /usr/src/app
RUN cargo build --release

# Stage 2: Final
FROM debian:bookworm-slim AS final
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/target/release/ca-server /usr/local/bin/
COPY certs/ca.crt /certs/ca.crt
COPY certs/ca.key /certs/ca.key
EXPOSE 8000
CMD ["/usr/local/bin/ca-server"]