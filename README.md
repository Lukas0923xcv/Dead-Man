# SecureVault: Zero-Knowledge 256-Bit Dual-Key Split Encryption Server

A turnkey, intercept-proof web application and REST API for Linux that guarantees **Zero-Knowledge End-to-End Encryption (E2EE)** using the **Web Crypto API (AES-256-GCM)** and **256-Bit Split Keys**, with device binding in **Normal Mode** and **Inherited Mode** email handover.

---

## 🛡️ Zero-Knowledge E2EE Architecture (Intercept-Proof)

Plaintext is **never** transmitted over the network or exposed to the server:

```text
[ 1. IN-BROWSER ENCRYPTION (Web Crypto API) ]
• User enters text in the web interface.
• Browser generates 256-bit Key A and Key B locally using window.crypto.
• Browser encrypts the plaintext locally in browser memory (AES-256-GCM).
• ONLY the encrypted ciphertext (and Key B) is sent across the network.
• Result: The server and any network eavesdroppers NEVER see the plaintext.

[ 2. IN-BROWSER DECRYPTION ]
• Browser retrieves ciphertext (and Key B if on authorized device in Normal Mode).
• Browser combines Master Key = Key A ⊕ Key B.
• Decryption happens locally inside browser memory.
• Plaintext is rendered on screen without the server ever seeing the decrypted data.
```

---

## Quick Start: 1-Command Docker Deployment

On your Linux server:

```bash
# 1. Pull the repository
git clone https://github.com/Lukas0923xcv/Linux-test.git
cd Linux-test

# 2. Run the automated installer (installs Docker if needed & starts container)
bash setup.sh
```

### Or if Docker is already installed:
```bash
sudo docker compose up -d --build
```

Open your browser at:
- **Primary Vault Web App**: **`http://<SERVER_IP>:8080/`**
- **Dead Man's Switch Monitor**: **`http://<SERVER_IP>:8081/`** (real-time overview of 8-digit codes, armed/inherited mode, and countdown timers).

---

## Useful Docker Commands

| Command | Action |
| :--- | :--- |
| `sudo docker compose up -d --build` | Build and start container in the background |
| `sudo docker compose logs -f` | View real-time container logs |
| `sudo docker compose restart` | Restart container |
| `sudo docker compose down` | Stop container |

---

## Enabling SSL / HTTPS Transport Encryption

To enable HTTPS transport security:

1. Set `SSL_ENABLED=true` in `.env`:
   ```env
   SSL_ENABLED=true
   ```
2. Restart container:
   ```bash
   sudo docker compose up -d --build
   ```
*(SecureVault automatically generates a self-signed TLS certificate if none is present).*

---

## Testing

```bash
python3 -m unittest discover -s tests -v
```
