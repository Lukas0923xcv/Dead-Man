"""
Email delivery service using standard SMTP (e.g. Gmail).
Sends Key B to designated recipient email upon switching to Inherited Mode.
Supports TLS (port 587), SSL (port 465), and provides live connection diagnostics.
"""

import os
import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Tuple


def get_smtp_config() -> Dict[str, str]:
    """Dynamically read and sanitize SMTP configuration from environment."""
    host = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
    try:
        port = int(os.getenv("SMTP_PORT", "587").strip())
    except ValueError:
        port = 587

    user = os.getenv("SMTP_USER", "").strip()
    # Strip spaces from App Passwords (e.g. Gmail 16-character passwords with spaces)
    password = os.getenv("SMTP_PASS", "").replace(" ", "").strip()
    sender = os.getenv("SMTP_FROM", "").strip() or user or "noreply@securevault.local"

    return {
        "host": host,
        "port": port,
        "user": user,
        "pass": password,
        "from": sender,
    }


def is_smtp_configured() -> bool:
    """Check if live SMTP credentials are configured."""
    config = get_smtp_config()
    return bool(config["user"] and config["pass"])


def send_key_b_email(
    to_email: str,
    code: str,
    key_b: str,
    server_url: str = "http://localhost:8080",
) -> Tuple[bool, str]:
    """
    Send an email containing Key B and the storage code to the recipient.
    
    :param to_email: Destination recipient email address.
    :param code: 8-character storage code.
    :param key_b: Base64 256-bit Key B.
    :param server_url: Web vault URL for instructions.
    :return: (success: bool, status_message: str)
    """
    if not to_email or "@" not in to_email:
        return False, "Invalid recipient email address."

    config = get_smtp_config()
    subject = f"[SecureVault] Key B Released for Code: {code}"

    # Plain text version
    text_content = f"""Hello,

Custody for encrypted record '{code}' has been transferred to Inherited Mode.

Below is your Key B:
--------------------------------------------------
Storage Code : {code}
Key B        : {key_b}
--------------------------------------------------

To decrypt the original data, visit:
{server_url}

Navigate to the 'Decrypt' tab and provide:
1. Storage Code: {code}
2. Key A (Provided by the owner)
3. Key B (Provided above)

Both Key A and Key B are required to decrypt.

SecureVault Team
"""

    # HTML version
    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0d1117; color: #c9d1d9; padding: 20px; }}
    .box {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; max-width: 600px; margin: 0 auto; }}
    h2 {{ color: #f0f6fc; margin-top: 0; }}
    .key-box {{ background: #090d13; border: 1px solid #bc8cff55; color: #bc8cff; font-family: monospace; font-size: 14px; padding: 12px; border-radius: 6px; word-break: break-all; margin: 12px 0; }}
    .code-box {{ background: #090d13; border: 1px solid #f2cc6055; color: #f2cc60; font-family: monospace; font-size: 16px; font-weight: bold; padding: 8px 12px; border-radius: 6px; display: inline-block; }}
    .footer {{ font-size: 12px; color: #8b949e; margin-top: 20px; }}
  </style>
</head>
<body>
  <div class="box">
    <h2>🏛️ SecureVault — Inherited Custody Handover</h2>
    <p>Custody for encrypted record has been transferred to <strong>Inherited Mode</strong>.</p>
    
    <p><strong>Storage Code:</strong></p>
    <div class="code-box">{code}</div>

    <p style="margin-top: 16px;"><strong>Key B (Released Key):</strong></p>
    <div class="key-box">{key_b}</div>

    <p style="margin-top: 16px;">To decrypt this record, visit <a href="{server_url}" style="color: #58a6ff;">{server_url}</a> and enter both <strong>Key A</strong> and <strong>Key B</strong>.</p>

    <div class="footer">SecureVault • Dual-Key Split Encryption</div>
  </div>
</body>
</html>
"""

    # If live credentials are not set, log simulation cleanly to stderr
    if not is_smtp_configured():
        sys.stderr.write(
            f"[EmailService - Simulation] Email to <{to_email}> for code '{code}':\n"
            f"  -> Key B: {key_b}\n"
            f"  (SMTP_USER or SMTP_PASS not set in environment/.env)\n"
        )
        return True, f"Key B dispatched to {to_email} (Simulation Mode: SMTP_USER not set in .env)."

    # Send live email via SMTP
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = config["from"]
        msg["To"] = to_email

        part1 = MIMEText(text_content, "plain", "utf-8")
        part2 = MIMEText(html_content, "html", "utf-8")
        msg.attach(part1)
        msg.attach(part2)

        # Connect via SSL or STARTTLS based on port
        if config["port"] == 465:
            with smtplib.SMTP_SSL(config["host"], config["port"], timeout=12) as server:
                server.login(config["user"], config["pass"])
                server.sendmail(config["from"], [to_email], msg.as_string())
        else:
            with smtplib.SMTP(config["host"], config["port"], timeout=12) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(config["user"], config["pass"])
                server.sendmail(config["from"], [to_email], msg.as_string())

        sys.stderr.write(f"[EmailService - Success] Key B sent to {to_email} via {config['host']}:{config['port']}\n")
        return True, f"Key B successfully emailed to {to_email} via {config['host']}."

    except smtplib.SMTPAuthenticationError as auth_err:
        err_msg = (
            f"Gmail/SMTP Authentication failed for {config['user']}. "
            f"If using Gmail, you must use a 16-character App Password (not your regular account password). Details: {auth_err}"
        )
        sys.stderr.write(f"[EmailService - AuthError] {err_msg}\n")
        return False, err_msg
    except Exception as e:
        err_msg = f"SMTP error ({config['host']}:{config['port']}): {e}"
        sys.stderr.write(f"[EmailService - Error] {err_msg}\n")
        return False, err_msg


def test_smtp_connection(test_recipient: str = None) -> Tuple[bool, str]:
    """Test SMTP connection and optionally send a test email."""
    if not is_smtp_configured():
        return False, "SMTP is not configured. Please set SMTP_USER and SMTP_PASS in .env"

    config = get_smtp_config()
    to_email = test_recipient or config["user"]

    try:
        if config["port"] == 465:
            with smtplib.SMTP_SSL(config["host"], config["port"], timeout=10) as server:
                server.login(config["user"], config["pass"])
        else:
            with smtplib.SMTP(config["host"], config["port"], timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(config["user"], config["pass"])

        # If test recipient provided, send a quick test message
        if test_recipient:
            msg = MIMEText("This is a test email from SecureVault to verify SMTP delivery.", "plain", "utf-8")
            msg["Subject"] = "[SecureVault] SMTP Test Verification"
            msg["From"] = config["from"]
            msg["To"] = to_email

            if config["port"] == 465:
                with smtplib.SMTP_SSL(config["host"], config["port"], timeout=10) as server:
                    server.login(config["user"], config["pass"])
                    server.sendmail(config["from"], [to_email], msg.as_string())
            else:
                with smtplib.SMTP(config["host"], config["port"], timeout=10) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(config["user"], config["pass"])
                    server.sendmail(config["from"], [to_email], msg.as_string())

        return True, f"SMTP connection to {config['host']}:{config['port']} succeeded as '{config['user']}'."
    except smtplib.SMTPAuthenticationError as auth_err:
        return False, f"Authentication failed: Check your Gmail App Password. Error: {auth_err}"
    except Exception as e:
        return False, f"Connection failed to {config['host']}:{config['port']}: {e}"
