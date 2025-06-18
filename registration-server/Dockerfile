FROM rust:1.81-slim AS builder

RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY registration-server/Cargo.toml registration-server/Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

COPY registration-server/src ./src

RUN cargo build --release

FROM debian:bookworm-slim AS final

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/registration-server /usr/local/bin/

COPY certs /certs

EXPOSE 8443

CMD ["/usr/local/bin/registration-server"]