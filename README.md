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
git clone https://github.com/Lukas0923xcv/Dead-Man.git
cd Dead-Man

# 2. Run the automated installer (installs Docker if needed & starts container)
bash setup.sh
```

### Or if Docker is already installed:
```bash
sudo docker compose up -d --build
```

Open your browser at:
- **Primary Vault Web App**: **`http://<SERVER_IP>:8080/`**
- **Dead Man's Switch Monitor**: **`http://<SERVER_IP>:8081/`** (real-time overview of 16-character codes, armed/inherited mode, and countdown timers).

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

## 📧 Email Configuration & Gmail App Password Setup (Key B Automated Dispatch)

SecureVault automatically dispatches **Key B** and a **1-click direct decryption link** to the designated recipient email(s) whenever the **30-day dead man's switch triggers** or when manual emergency handover is executed.

To enable live email delivery via Gmail:

### 1. Generate a Gmail App Password
1. Sign in to your Google Account and navigate to **[Google Security](https://myaccount.google.com/security)**.
2. Verify that **2-Step Verification** (2FA) is turned **ON**.
3. Open **[Google App Passwords](https://myaccount.google.com/apppasswords)** (or search *"App passwords"* in your Google Account search bar).
4. Enter an app name (e.g. `SecureVault` or `DeadMan`) and click **Create**.
5. Google will display a **16-character App Password** (formatted like `abcd efgh ijkl mnop`).
6. Copy this 16-character code (remove any spaces).

### 2. Configure Your `.env` File
Open the `.env` file in your terminal editor (create it from `.env.example` if it doesn't exist yet):

```bash
# 1. Create .env from template if missing
cp -n .env.example .env

# 2. Open and edit the file
nano .env
```
*(In `nano`: Make your edits, press `Ctrl + O` then `Enter` to save, and `Ctrl + X` to exit. Alternatively, you can use `vim .env` or `code .env`).*

Paste and adapt your configuration:

```env
# Primary Server Configuration
PORT=8080
MONITOR_PORT=8081
KEY_BITS=256
STORAGE_DIR=/app/data/vault
USER_STORAGE_LIMIT_BYTES=10737418240

# Gmail / SMTP Settings for automated Key B dispatch
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_actual_email@gmail.com
SMTP_PASS=abcdefghijklmnop
SMTP_FROM=your_actual_email@gmail.com
```

> [!NOTE]
> **Privacy & Credential Safety**: The `.env` file is strictly ignored by `.gitignore` and is **never committed to Git or pushed to GitHub**. Always keep your `.env` file local on your server.

### 3. Restart Container to Apply
```bash
sudo docker compose down && sudo docker compose up -d --build
```
Once configured:
- SecureVault logs will confirm: `Email Delivery: Configured (Gmail/SMTP)`.
- Key B notifications will automatically be emailed to the primary and secondary recipients upon 30 days of inactivity.
- If `SMTP_USER` and `SMTP_PASS` are left empty, SecureVault operates in **Simulation Mode** (printing Key B to container logs for development/testing).

---

## 🏛️ Dead Man's Switch & Data Sovereignty Policy

SecureVault is engineered specifically for **automated cryptographic handover and emergency succession**:
- **Normal Mode**: Active as long as owner activity is registered within the 30-day inactivity window.
- **Inherited Mode**: Triggered after 30 days of inactivity (or via immediate manual handover). Key B is automatically dispatched to the recipient and wiped from server memory.
- **30-Day Retrieval Window & Auto-Purge**: Following key release, the recipient has **30 days** to retrieve and decrypt the files. Once this window elapses, **all encrypted records are permanently purged from disk** to guarantee absolute data sovereignty.
- **Ongoing Protection**: To maintain continuous emergency custody for retrieved notes or files, simply create a fresh encryption.

---

## Testing

```bash
python3 -m unittest discover -s tests -v
```
