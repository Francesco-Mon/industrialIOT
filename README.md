# Secure Device Registration System with Rust and etcd

This project implements a secure, robust, and scalable system for device registration and authentication, designed for IoT and distributed systems environments. The solution is written entirely in **Rust** and is based on a **mutual TLS (mTLS) authentication** model, featuring an **online Certificate Authority (CA) service** for dynamic identity provisioning.

The entire architecture is containerized with **Docker** and orchestrated via **Docker Compose**, ensuring reproducibility and a clean deployment environment.

## System Architecture

The system is built on a microservice architecture, where each component has a clear and distinct responsibility. This design promotes maintainability, independent scalability, and fault isolation.

The main components are:
1.  **CA Server**: A Rust microservice acting as an online Certificate Authority. Its sole responsibility is to receive Certificate Signing Requests (CSRs) from new devices, sign them using the CA's private key, and register the issued certificate in `etcd`.
2.  **Registration Server**: The main gateway for devices. It is an asynchronous TCP server that accepts mTLS connections. Its logic is twofold:
    -   **Authentication:** It validates the client's certificate against the trusted CA during the TLS handshake.
    -   **Authorization & Business Logic:** It verifies in `etcd` that the presented certificate was indeed issued by our CA, and then manages the device's state (initial registration, ongoing heartbeats).
3.  **etcd**: A distributed key-value data store, chosen for its strong consistency guarantees (based on the Raft algorithm). It serves as the single source of truth for both the certificates issued by the CA and the state metadata of registered devices.
4.  **Client (Device)**: A Rust application simulating an IoT device. It implements the full dynamic provisioning workflow.

## Dynamic Provisioning and Registration Workflow

A core feature of the system is its zero-touch provisioning workflow for new devices:

1.  **Key Generation:** On first boot, a new client device generates an RSA 2048-bit key pair locally.
2.  **CSR Creation:** Using its new public key, the device creates a CSR in PEM format, including a unique Common Name (CN).
3.  **Request to CA:** The client sends the CSR via an HTTP POST request to the `/sign-csr` endpoint of the `ca-server`.
4.  **Signing and Storage:** The `ca-server` validates the CSR, signs it with the CA's private key to generate a valid X.509 certificate, and stores a copy of this new certificate in `etcd`.
5.  **Certificate Delivery:** The signed certificate is returned to the client in the HTTP response.
6.  **Persistence:** The client securely stores its private key and the newly received certificate locally for future sessions.
7.  **Registration:** Now provisioned, the client connects to the `registration-server` using mTLS and sends a `REGISTER` command. The server validates the certificate and checks for its presence in `etcd` to finalize the registration by creating a state record for the device.

## Key Features

- ✅ **Multi-Layered Security**: mTLS authentication, an online CA for identity control, and service isolation via a private Docker network.
- ✅ **Dynamic Provisioning**: Devices auto-configure themselves on first boot, eliminating the need for manual key distribution.
- ✅ **Efficient Binary Protocol**: Communication uses a custom TCP protocol with a length-prefix header and `bincode` serialization, ideal for low-bandwidth environments.
- ✅ **Fault Tolerance & Resilience**: The server is designed to handle temporary disconnections from `etcd` and uses atomic transactions for critical operations.
- ✅ **Reproducible Deployment**: The entire architecture is launched with a single `docker-compose up` command.
- ✅ **Monitoring**: Each service exposes a `/health` endpoint and produces structured (JSON) logs via the `tracing` crate for easy integration with observability platforms.
- ✅ **Integrated Testing**: The project includes a load-testing tool to simulate and validate the system's ability to handle high concurrency.

## Technology Stack

- **Language**: Rust (2021 Edition)
- **Asynchronous Networking**: Tokio, `rustls` for TLS 1.3
- **Web Framework (CA Server)**: Axum
- **Cryptography**: `openssl` crate for key and certificate management
- **Data Store**: `etcd` v3.5
- **Protocol**: Custom Binary TCP with `bincode`
- **Deployment**: Docker, Docker Compose

## Execution and Demo Guide

### Prerequisites
-   **Docker** and **Docker Compose** installed and running.
-   **Rust** and **Cargo** installed.

### 1. Infrastructure Startup
This command builds the Docker images for the servers and launches the entire stack in the background.

```bash
# From the project's root directory
docker-compose up --build -d
```
Wait about 30-40 seconds, then verify that all services are healthy:
```bash
docker ps
# The output should show all 3 containers with STATUS (healthy)
```

### 2. Running the Client (Provisioning & Operation)
The single client demonstrates the full workflow, including identity persistence.

**First Run (Provisioning):**
```bash
# Clean up any previous identity files
rm -f registration-client/device.key registration-client/device.crt

# Run the client
cd registration-client
cargo run
```
*Expected Output*: You will see logs detailing the creation of a new identity, communication with the CA, followed by registration and heartbeats.

**Second Run (Reuse):**
```bash
# Run the client again
cargo run
```
*Expected Output*: You will see the message "Identity found on disk, loading...", followed immediately by the connection to the server.

## Testing

### Load Testing
To simulate multiple independent devices provisioning and connecting concurrently:

```bash
# In the test terminal, increase the open file limit (macOS/Linux)
ulimit -n 4096

# Navigate to the load-tester directory
cd load-tester

# Run the test with 1000 concurrent clients in optimized mode
cargo run --release 1000
```
Monitor the output of the `docker-compose logs -f` terminal to observe the server handling the concurrent load.

## Design Choices and Future Work

- **Microservice Architecture**: Separating the logic into three distinct services (`ca-server`, `registration-server`, `etcd`) enhances maintainability, scalability, and security by following the "separation of concerns" principle.
- **Future Work**:
  - **Kubernetes Deployment**: To achieve true high availability and horizontal scaling, the next step would be to deploy the stack to a Kubernetes cluster.
  - **CI/CD Pipeline**: Implement a workflow on GitHub Actions to automate testing, security scanning, and the building/publishing of Docker images on every commit.
  - **Enhanced CA Security**: In a production environment, the CA's private key would be protected by a Hardware Security Module (HSM) or a cloud-based key management service (e.g., AWS KMS) instead of being stored on a filesystem.
```
