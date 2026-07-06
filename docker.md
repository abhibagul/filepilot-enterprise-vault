# FilePilot — Corporate Vault Integration Microservice

![Docker Image](https://img.shields.io/badge/docker-ready-blue.svg?logo=docker)
![License](https://img.shields.io/badge/License-UNLICENSED-red.svg)

This microservice simulates or proxies a HashiCorp Vault server, allowing organizations to securely serve Connection Profiles to FilePilot clients over their intranet. It is designed to act as an enterprise config server, managing Key Encryption Keys (KEK), Data Encryption Keys (DEK), and compliance-checked remote connection configurations.

---

## 🖥️ Admin Console Preview

![Enterprise Console Dashboard](https://raw.githubusercontent.com/abhibagul/filepilot-enterprise-vault/refs/heads/main/admin/enterprise.png)

---

## 🚀 Quick Start (Docker Run)

Start the container mapping port `8443` on the host to port `8443` inside the container. Ensure you pass a 256-bit master key and mount a volume to persist configuration data:

```bash
docker run -d \
  -p 8443:8443 \
  -e VAULT_MASTER_KEY="your-super-secret-256-bit-hex-key" \
  -v ./data:/app/data \
  --name filepilot-vault \
  abbybagul/filepilot-enterprise-vault:latest
```

Once running, navigate to:
👉 **`http://localhost:8443/admin`** to complete the Web Setup Wizard.

---

## ⚙️ Docker Compose Configuration (`docker-compose.yml`)

To orchestrate the vault microservice with a Postgres database for production environments, use the following `docker-compose.yml`:

```yaml
version: '3.8'

services:
  vault:
    image: abbybagul/filepilot-enterprise-vault:latest
    ports:
      - "8443:8443"
    environment:
      - PORT=8443
      - NODE_ENV=production
      - VAULT_DATA_DIR=/app/data
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

## 🚨 Production Deployment Checklist

* **Production Database:** Do **NOT** use SQLite for production. Deploy using **PostgreSQL** or **MySQL** to enable proper database-level deletion prevention triggers. Restrict database user privileges (revoke `DELETE` / `DROP` / `TRUNCATE` privileges on audit logs).
* **Master Encryption Key:** Always set the `VAULT_MASTER_KEY` environment variable as a 256-bit hex/base64 string. Never rely on the auto-generated `.vault_key` file-based fallback on disk in a containerized environment, as containers are ephemeral.
* **Persistent Data Volume:** Always map the `/app/data` path to a persistent volume (e.g. `-v ./data:/app/data`) to prevent configuration data loss when container lifecycles end.
* **Network Security (TLS/HTTPS):** Run the microservice behind a reverse proxy (e.g. Nginx, Cloudflare, AWS ALB) configured for HTTPS/TLS to protect credentials and tokens in transit.

---

## 🔒 Bring Your Own KMS (BYOK)

The Corporate Vault microservice supports Bring-Your-Own-KMS (BYOK) configurations. Enterprise administrators can offload Key Encryption Key (KEK) management and remote wrap/unwrap operations to their own customer-managed KMS systems:
* **AWS KMS** (`aws-kms`)
* **Azure Key Vault** (`azure-keyvault`)
* **HashiCorp Vault** (`hashicorp-vault`)
