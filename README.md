# FilePilot — Corporate Vault Integration Microservice

[![Docker Image](https://img.shields.io/badge/docker-ready-blue.svg?logo=docker)](https://hub.docker.com/)
[![License](https://img.shields.io/badge/License-UNLICENSED-red.svg)](#)

This microservice simulates or proxies a HashiCorp Vault server, allowing organizations to securely serve Connection Profiles to FilePilot clients over their intranet. It is designed to act as an enterprise config server, managing Key Encryption Keys (KEK), Data Encryption Keys (DEK), and compliance-checked remote connection configurations.

---

## 🚨 Production Deployment Checklist

Before deploying this microservice in a production environment, ensure the following security requirements are met:
* **Production Database:** Do **NOT** use SQLite for production. Deploy using **PostgreSQL** or **MySQL** to enable proper database-level deletion prevention triggers. Restrict database user privileges (revoke `DELETE` / `DROP` / `TRUNCATE` privileges on audit logs).
* **Master Encryption Key:** Always set the `VAULT_MASTER_KEY` environment variable as a 256-bit hex/base64 string. Never rely on the auto-generated `.vault_key` file-based fallback on disk in a containerized environment, as containers are ephemeral.
* **Default Credentials:** Always run the Setup Wizard (`/admin/install.html` on first boot) to establish a strong custom admin password. If default `admin`/`vault-admin-pass` credentials are ever initialized, change them immediately in the admin settings console.
* **Network Security (TLS/HTTPS):** Run the microservice behind a reverse proxy (e.g., Nginx, Cloudflare, AWS ALB) configured for HTTPS/TLS to protect credentials and tokens in transit.
* **IP Allowlisting:** Configure strict IP allowlists for all Vault Groups to restrict client synchronization access to designated enterprise subnets and VPN endpoints.

---

## 📦 Getting Started

### Method 1: Local Node.js Setup

1. **Install Dependencies**:
   ```bash
   npm install
   ```
2. **Start the Microservice**:
   ```bash
   npm start
   ```
   The server will start listening on port `8200`.

---

### Method 2: Docker Setup (Recommended)

This microservice comes containerized with a lightweight Alpine-based Node.js Dockerfile.

#### 1. Build the Docker Image Locally
```bash
docker build -t filepilot-enterprise-vault:latest .
```

#### 2. Run the Container
Run the container and map port `8200` to your host machine:
```bash
docker run -d \
  -p 8200:8200 \
  -e VAULT_MASTER_KEY="your-super-secret-256-bit-hex-key" \
  -v filepilot-vault-data:/app/data \
  --name filepilot-vault \
  filepilot-enterprise-vault:latest
```

> [!NOTE]
> If you are using the default SQLite backend, it is recommended to map a Docker volume or local directory to mount the database persistently. To change the SQLite database location, configure it through the admin setup page (`/admin/install.html`) on first launch.

#### 3. Docker Compose Configuration (`docker-compose.yml`)
To orchestrate the vault microservice with a Postgres database for enterprise production, configure `docker-compose.yml` as follows:

```yaml
version: '3.8'

services:
  vault:
    image: filepilot-enterprise-vault:latest
    build: .
    ports:
      - "8200:8200"
    environment:
      - PORT=8200
      - NODE_ENV=production
      - VAULT_MASTER_KEY=4a6f6e617468616e206973206120736563726574206b65792121212121212121
    volumes:
      - vault_data:/app/data
    depends_on:
      - db

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=filepilot_vault
      - POSTGRES_USER=vault_admin
      - POSTGRES_PASSWORD=strong_db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  vault_data:
  postgres_data:
```

---

## 🚀 Pushing to Docker Hub & CI/CD

This repository includes a preconfigured GitHub Actions workflow in `.github/workflows/docker-publish.yml` to automate builds and pushes.

### Prerequisites for GitHub Actions:
1. Go to your GitHub repository -> **Settings** -> **Secrets and variables** -> **Actions**.
2. Add the following **Repository Secrets**:
   * `DOCKERHUB_USERNAME`: Your Docker Hub username.
   * `DOCKERHUB_TOKEN`: A Personal Access Token (PAT) generated from your Docker Hub account with write access.
3. The workflow will automatically trigger, build, tag, and push the image to Docker Hub whenever you push a semantic version tag (e.g. `v1.0.0`) or publish a GitHub release.

---

## 🔒 Bring Your Own KMS (BYOK)

The Corporate Vault microservice supports Bring-Your-Own-KMS (BYOK) configurations. Enterprise administrators can offload Key Encryption Key (KEK) management and remote wrap/unwrap operations to their own customer-managed KMS systems (AWS KMS, Azure Key Vault, or HashiCorp Vault).

### Supported KMS Providers & Configuration

#### 1. Local (Default)
Uses the default app-managed `VAULT_MASTER_KEY` environment variable or local master key file to perform wrapping/unwrapping locally via AES-256-GCM. No external cloud credentials are required.

#### 2. AWS KMS (`aws-kms`)
Calls AWS KMS remotely to perform `Encrypt`, `Decrypt`, and `DescribeKey` operations on a customer-provided KMS Key ARN.
* **Non-secret Configuration (`kms_config`):**
  * `region`: The target AWS Region (e.g. `us-east-1`).
  * `keyArn`: The full AWS KMS Key ARN.
* **Credentials (`kms_credentials`):**
  * `accessKeyId`: AWS Access Key ID.
  * `secretAccessKey`: AWS Secret Access Key.

#### 3. Azure Key Vault (`azure-keyvault`)
Performs `wrapKey` and `unwrapKey` operations using an Azure Key Vault RSA key (via `RSA-OAEP-256`).
* **Non-secret Configuration (`kms_config`):**
  * `vaultUrl`: The target Key Vault endpoint URL (e.g. `https://myvault.vault.azure.net`).
  * `keyName`: The Key Name.
* **Credentials (`kms_credentials`):**
  * `tenantId`: Azure AD Tenant ID.
  * `clientId`: Client App Registration ID.
  * `clientSecret`: Client Secret.

#### 4. HashiCorp Vault (`hashicorp-vault`)
Uses HashiCorp Vault's **Transit Secrets Engine** `encrypt` and `decrypt` endpoints over HTTP.
* **Non-secret Configuration (`kms_config`):**
  * `vaultAddr`: The address of the Vault server (e.g. `https://vault.corp.internal:8200`).
  * `transitKeyName`: Transit engine key name.
* **Credentials (`kms_credentials`):**
  * `vaultToken`: Vault access token.
  * `roleId`: AppRole Role ID.
  * `secretId`: AppRole Secret ID.

---

## 🔒 Tamper-Evidence & Deletion Prevention Security Boundary

The security audit logging system uses a cryptographic hash-chain to record actions, with database-level deletion prevention triggers.

| Database Engine | Application-level Deletion Block | Database-level Deletion Block | Tamper Detection (Hash-Chain Verification) | OS-level / Filesystem Access Protection |
| --- | --- | --- | --- | --- |
| **MySQL** | Yes (No DELETE/TRUNCATE endpoints) | Yes (`prevent_delete_transferlog` trigger blocks direct DELETE/TRUNCATE) | Yes (`verify-full` detects any hash/chain mismatch) | Admin should configure user privileges: revoke `DELETE` / `DROP` |
| **PostgreSQL** | Yes (No DELETE/TRUNCATE endpoints) | Yes (`prevent_delete_transferlog` trigger blocks direct DELETE/TRUNCATE) | Yes (`verify-full` detects any hash/chain mismatch) | Admin should configure user privileges: revoke `DELETE` / `TRUNCATE` |
| **SQLite** | Yes (No DELETE/TRUNCATE endpoints) | Yes (`prevent_delete_transferlog` trigger blocks direct DELETE) | Yes (`verify-full` detects any hash/chain mismatch) | None (Any user with read/write access to the database file can modify or delete the file directly) |

---

## 🔒 SIEM Webhook HMAC Signature Verification

This vault microservice sends JSON payloads of all security audit logs to the configured SIEM Webhook URL. Each webhook payload is cryptographically signed using the `siem_webhook_secret` using HMAC-SHA256.

The signature is sent in the HTTP header:
`X-Vault-Signature-256: sha256=<hex signature>`

---

## 🔗 Integrating with FilePilot Client

1. Boot up this microservice (either locally or containerized).
2. Open the FilePilot client application.
3. Navigate to **Settings** -> **Enterprise Sync**.
4. Configure the Vault URL: `http://<your-vault-host>:8200/v1/secret/data/filepilot/profiles`.
5. Enter the vault access token or credentials configured in the admin panel.
6. Click **Sync Profiles Now** to retrieve connection profiles over the secure corporate network.
