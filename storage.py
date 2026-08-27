"""
File-based storage engine for Dual-Key split encrypted records.
Stores vault records under unique 16-character reference codes with device binding,
last activity tracking, and Normal/Inherited mode support.
"""

import datetime
import json
import os
import re
from typing import Dict, List, Optional, Tuple

import hashlib
import secrets

DEFAULT_STORAGE_DIR = os.getenv("STORAGE_DIR", os.path.join(os.path.dirname(__file__), "data", "vault"))
DEFAULT_USERS_DIR = os.getenv("USERS_DIR", os.path.join(os.path.dirname(__file__), "data", "users"))
DEFAULT_SESSIONS_DIR = os.getenv("SESSIONS_DIR", os.path.join(os.path.dirname(__file__), "data", "sessions"))

# Validator for alphanumeric storage codes (standard: 16 chars, flexible 8-32 chars)
CODE_PATTERN = re.compile(r"^[a-zA-Z0-9]{8,32}$")
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")


def ensure_storage_dir(storage_dir: str = DEFAULT_STORAGE_DIR) -> str:
    """Ensure that the storage directory exists and return its path."""
    os.makedirs(storage_dir, exist_ok=True)
    return storage_dir


def ensure_users_dir(users_dir: str = DEFAULT_USERS_DIR) -> str:
    """Ensure that the users directory exists and return its path."""
    os.makedirs(users_dir, exist_ok=True)
    return users_dir


def ensure_sessions_dir(sessions_dir: str = DEFAULT_SESSIONS_DIR) -> str:
    """Ensure that the sessions directory exists and return its path."""
    os.makedirs(sessions_dir, exist_ok=True)
    return sessions_dir


def save_session(
    token: str,
    username: str,
    duration_days: int = 30,
    sessions_dir: str = DEFAULT_SESSIONS_DIR,
) -> Dict:
    """Persist an authenticated user session to disk with expiration timestamp."""
    ensure_sessions_dir(sessions_dir)
    clean_token = token.strip()
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(days=duration_days)

    session_data = {
        "token": clean_token,
        "username": username.strip(),
        "created_at": now.isoformat(),
        "last_active_at": now.isoformat(),
        "expires_at": expires.isoformat(),
    }

    file_path = os.path.join(sessions_dir, f"{clean_token}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(session_data, f, indent=2)

    return session_data


def get_session_username(
    token: str, sessions_dir: str = DEFAULT_SESSIONS_DIR
) -> Optional[str]:
    """Retrieve username for a session token if valid and unexpired."""
    if not token or not isinstance(token, str):
        return None

    clean_token = token.strip()
    file_path = os.path.join(sessions_dir, f"{clean_token}.json")
    if not os.path.isfile(file_path):
        return None

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            session_data = json.load(f)

        expires_str = session_data.get("expires_at")
        if expires_str:
            clean_exp = expires_str.replace("Z", "+00:00")
            exp_time = datetime.datetime.fromisoformat(clean_exp)
            if exp_time.tzinfo is None:
                exp_time = exp_time.replace(tzinfo=datetime.timezone.utc)

            now = datetime.datetime.now(datetime.timezone.utc)
            if now > exp_time:
                try:
                    os.remove(file_path)
                except Exception:
                    pass
                return None

        # Touch last_active_at
        try:
            session_data["last_active_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(session_data, f, indent=2)
        except Exception:
            pass

        return session_data.get("username")
    except Exception:
        return None


def delete_session(
    token: str, sessions_dir: str = DEFAULT_SESSIONS_DIR
) -> bool:
    """Delete a persisted session file from disk upon logout."""
    if not token or not isinstance(token, str):
        return False
    clean_token = token.strip()
    file_path = os.path.join(sessions_dir, f"{clean_token}.json")
    try:
        if os.path.isfile(file_path):
            os.remove(file_path)
            return True
        return False
    except Exception:
        return False


def validate_username(username: str) -> bool:
    """Validate username format (3-32 chars, alphanumeric and _.-)."""
    if not isinstance(username, str):
        return False
    return bool(USERNAME_PATTERN.match(username.strip()))


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Securely hash a password using PBKDF2-HMAC-SHA256 with 100,000 iterations.
    Returns (hash_hex, salt_hex).
    """
    if salt is None:
        salt_bytes = secrets.token_bytes(16)
        salt_hex = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt)
        salt_hex = salt

    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt_bytes, 100_000
    ).hex()
    return pwd_hash, salt_hex


def get_user_file_path(username: str, users_dir: str = DEFAULT_USERS_DIR) -> str:
    """Get the file path for a user record."""
    clean_user = username.strip().lower()
    if not validate_username(clean_user):
        raise ValueError(f"Invalid username '{username}'. Must be 3-32 alphanumeric characters.")
    return os.path.join(users_dir, f"{clean_user}.json")


def user_exists(username: str, users_dir: str = DEFAULT_USERS_DIR) -> bool:
    """Check if a user account already exists."""
    try:
        path = get_user_file_path(username, users_dir)
        return os.path.isfile(path)
    except ValueError:
        return False


def save_user(username: str, password: str, users_dir: str = DEFAULT_USERS_DIR) -> Dict:
    """Register and save a new user account."""
    ensure_users_dir(users_dir)
    clean_user = username.strip()
    if not validate_username(clean_user):
        raise ValueError("Username must be 3-32 characters (letters, digits, '.', '-', '_').")
    if len(password) < 4:
        raise ValueError("Password must be at least 4 characters.")
    if user_exists(clean_user, users_dir):
        raise ValueError(f"Username '{clean_user}' is already registered.")

    pwd_hash, salt = hash_password(password)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    user_record = {
        "username": clean_user,
        "password_hash": pwd_hash,
        "salt": salt,
        "created_at": now_iso,
        "last_login_at": now_iso,
    }

    file_path = get_user_file_path(clean_user, users_dir)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(user_record, f, indent=2)

    return {"username": clean_user, "created_at": now_iso}


def get_user(username: str, users_dir: str = DEFAULT_USERS_DIR) -> Optional[Dict]:
    """Load a user account record."""
    try:
        file_path = get_user_file_path(username, users_dir)
    except ValueError:
        return None

    if not os.path.isfile(file_path):
        return None

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def verify_user_password(username: str, password: str, users_dir: str = DEFAULT_USERS_DIR) -> bool:
    """Verify a user's password against stored PBKDF2 hash."""
    user = get_user(username, users_dir)
    if not user:
        return False

    stored_hash = user.get("password_hash")
    salt = user.get("salt")
    if not stored_hash or not salt:
        return False

    calc_hash, _ = hash_password(password, salt)
    if secrets.compare_digest(stored_hash, calc_hash):
        # Update last_login_at
        try:
            user["last_login_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            file_path = get_user_file_path(username, users_dir)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(user, f, indent=2)
        except Exception:
            pass
        return True
    return False


def validate_code(code: str) -> bool:
    """Check if the provided code is a valid alphanumeric identifier (e.g. 16 characters)."""
    if not isinstance(code, str):
        return False
    return bool(CODE_PATTERN.match(code.strip()))


def get_file_path(code: str, storage_dir: str = DEFAULT_STORAGE_DIR) -> str:
    """Get the sanitized absolute JSON file path for a code."""
    clean_code = code.strip()
    if not validate_code(clean_code):
        raise ValueError(f"Invalid code format '{code}'. Must be an alphanumeric string (8-32 characters).")
    return os.path.join(storage_dir, f"{clean_code}.json")


def code_exists(code: str, storage_dir: str = DEFAULT_STORAGE_DIR) -> bool:
    """Check if an encrypted vault record exists for the given code."""
    try:
        path = get_file_path(code, storage_dir)
        return os.path.isfile(path)
    except ValueError:
        return False


def save_vault_record(
    code: str,
    encrypted_text: str,
    server_key_b: Optional[str],
    recipient_email: Optional[str] = None,
    recipient_email_2: Optional[str] = None,
    owner_username: Optional[str] = None,
    device_id: Optional[str] = None,
    mode: str = "normal",
    inactivity_days: int = 30,
    auto_inherit: bool = True,
    storage_dir: str = DEFAULT_STORAGE_DIR,
) -> str:
    """
    Save a new vault record with ciphertext, server key (Key B), primary and secondary recipient emails,
    owner username, device binding ID, inactivity timeout days, and initial activity timestamp.
    """
    ensure_storage_dir(storage_dir)
    file_path = get_file_path(code, storage_dir)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    is_auto = bool(auto_inherit and int(inactivity_days) > 0)
    final_days = int(inactivity_days) if is_auto else 0

    record = {
        "code": code,
        "mode": mode,
        "auto_inherit": is_auto,
        "encrypted_text": encrypted_text.strip(),
        "server_key_b": server_key_b,
        "owner_username": owner_username.strip() if owner_username else None,
        "device_id": device_id.strip() if device_id else None,
        "recipient_email": recipient_email.strip() if recipient_email else None,
        "recipient_email_2": recipient_email_2.strip() if recipient_email_2 else None,
        "inactivity_days": final_days,
        "created_at": now_iso,
        "last_active_at": now_iso,
        "inherited_at": None,
        "killed_at": None,
    }

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    return file_path


def load_vault_record(code: str, storage_dir: str = DEFAULT_STORAGE_DIR) -> Optional[Dict]:
    """
    Load a vault record by 8-character code. Returns dict or None.
    """
    try:
        file_path = get_file_path(code, storage_dir)
    except ValueError:
        return None

    if not os.path.isfile(file_path):
        return None

    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def delete_vault_record(code: str, storage_dir: str = DEFAULT_STORAGE_DIR) -> bool:
    """
    Permanently delete an encrypted vault record from the filesystem.
    Returns True if file existed and was removed, False otherwise.
    """
    try:
        file_path = get_file_path(code, storage_dir)
        if os.path.isfile(file_path):
            os.remove(file_path)
            return True
        return False
    except Exception:
        return False


def touch_record_activity(code: str, storage_dir: str = DEFAULT_STORAGE_DIR) -> bool:
    """
    Update the last_active_at timestamp for a specific record.
    """
    record = load_vault_record(code, storage_dir)
    if record is None or record.get("mode") == "inherited":
        return False

    record["last_active_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    file_path = get_file_path(code, storage_dir)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    return True


def get_record_recipients(record: Dict) -> List[str]:
    """Extract list of clean recipient emails from a vault record."""
    if not record or not isinstance(record, dict):
        return []
    recipients: List[str] = []
    # 1. Primary recipient
    r1 = (record.get("recipient_email") or "").strip()
    if r1 and "@" in r1 and "." in r1.split("@")[-1]:
        recipients.append(r1)

    # 2. Secondary recipient
    r2 = (record.get("recipient_email_2") or "").strip()
    if r2 and "@" in r2 and "." in r2.split("@")[-1] and r2.lower() != r1.lower():
        recipients.append(r2)

    # 3. List format support
    for r in record.get("recipient_emails", []):
        r_clean = str(r).strip()
        if r_clean and "@" in r_clean and "." in r_clean.split("@")[-1] and r_clean.lower() not in [x.lower() for x in recipients]:
            recipients.append(r_clean)

    return recipients


def update_recipient_emails(
    code: str, email_1: str, email_2: Optional[str] = None, storage_dir: str = DEFAULT_STORAGE_DIR
) -> Dict:
    """
    Update primary and secondary recipient email addresses for an existing vault record in Normal mode.
    """
    record = load_vault_record(code, storage_dir)
    if record is None:
        raise ValueError(f"No vault record found for code '{code}'.")

    if record.get("mode") == "inherited":
        raise ValueError("Cannot change recipient email: Vault has already been transferred to Inherited mode.")

    clean_email_1 = (email_1 or "").strip()
    if not clean_email_1 or "@" not in clean_email_1 or "." not in clean_email_1.split("@")[-1]:
        raise ValueError("A valid primary email address with '@' and domain is required.")

    clean_email_2 = (email_2 or "").strip() if email_2 else None
    if clean_email_2:
        if "@" not in clean_email_2 or "." not in clean_email_2.split("@")[-1]:
            raise ValueError("The secondary email address must be valid with '@' and domain, or left empty.")

    record["recipient_email"] = clean_email_1
    record["recipient_email_2"] = clean_email_2
    file_path = get_file_path(code, storage_dir)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    return record


def update_recipient_email(
    code: str, new_email: str, storage_dir: str = DEFAULT_STORAGE_DIR
) -> Dict:
    """Legacy helper for updating single recipient email."""
    return update_recipient_emails(code, email_1=new_email, email_2=None, storage_dir=storage_dir)


def touch_device_activity(device_id: str, storage_dir: str = DEFAULT_STORAGE_DIR) -> int:
    """
    Update the last_active_at timestamp for all records bound to a given device_id.
    """
    if not device_id:
        return 0

    ensure_storage_dir(storage_dir)
    updated_count = 0
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for filename in os.listdir(storage_dir):
        if not filename.endswith(".json"):
            continue
        file_path = os.path.join(storage_dir, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                record = json.load(f)
            if record.get("device_id") == device_id and record.get("mode") == "normal":
                record["last_active_at"] = now_iso
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(record, f, indent=2)
                updated_count += 1
        except Exception:
            continue

    return updated_count


def get_inactive_expired_records(
    inactivity_days: int = 30, storage_dir: str = DEFAULT_STORAGE_DIR
) -> List[str]:
    """
    Scan all vault records and return codes of records that have exceeded the inactivity limit in Normal Mode.
    Uses each record's specific inactivity window (with fallback to server default).
    Ignores records where auto_inherit is explicitly disabled.
    """
    ensure_storage_dir(storage_dir)
    expired_codes = []
    now = datetime.datetime.now(datetime.timezone.utc)

    for filename in os.listdir(storage_dir):
        if not filename.endswith(".json"):
            continue
        file_path = os.path.join(storage_dir, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                record = json.load(f)

            if record.get("mode") != "normal" or not record.get("server_key_b"):
                continue

            if record.get("auto_inherit") is False:
                continue

            rec_inactivity = int(record.get("inactivity_days") or inactivity_days)
            if rec_inactivity <= 0:
                continue

            last_active_str = record.get("last_active_at") or record.get("created_at")
            if not last_active_str:
                continue

            cutoff_delta = datetime.timedelta(days=rec_inactivity)

            # Parse ISO timestamp (handling 'Z' or '+00:00')
            last_active_str = last_active_str.replace("Z", "+00:00")
            last_active = datetime.datetime.fromisoformat(last_active_str)
            if last_active.tzinfo is None:
                last_active = last_active.replace(tzinfo=datetime.timezone.utc)

            if (now - last_active) >= cutoff_delta:
                expired_codes.append(record.get("code") or filename[:-5])
        except Exception:
            continue

    return expired_codes


def disable_auto_inheritance(code: str, storage_dir: str = DEFAULT_STORAGE_DIR) -> Dict:
    """
    Permanently disable automated inheritance for a record (disconnects the Dead Man's Switch).
    Schedules data for final deletion in 30 days.
    """
    record = load_vault_record(code, storage_dir)
    if record is None:
        raise ValueError(f"No record found for code '{code}'.")
    if record.get("mode") == "inherited":
        raise ValueError(f"Record '{code}' has already been transferred to Inherited Mode.")

    now = datetime.datetime.now(datetime.timezone.utc)
    record["auto_inherit"] = False
    record["inactivity_days"] = 0
    record["mode"] = "stopped"
    record["killed_at"] = now.isoformat()
    record["recipient_email"] = None

    file_path = get_file_path(code, storage_dir)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    return record


def purge_expired_inherited_records(
    purge_days: int = 30, storage_dir: str = DEFAULT_STORAGE_DIR
) -> List[str]:
    """
    Purge and permanently delete vault files that have been in Inherited or Stopped Mode for 30+ days.
    """
    ensure_storage_dir(storage_dir)
    purged_codes = []
    now = datetime.datetime.now(datetime.timezone.utc)
    purge_delta = datetime.timedelta(days=purge_days)

    for filename in os.listdir(storage_dir):
        if not filename.endswith(".json"):
            continue
        file_path = os.path.join(storage_dir, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                record = json.load(f)

            mode = record.get("mode")
            if mode not in ("inherited", "stopped"):
                continue

            ts_str = record.get("inherited_at") if mode == "inherited" else record.get("killed_at")
            if not ts_str:
                continue

            clean_ts = ts_str.replace("Z", "+00:00")
            event_time = datetime.datetime.fromisoformat(clean_ts)
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=datetime.timezone.utc)

            if (now - event_time) >= purge_delta:
                code = record.get("code") or filename[:-5]
                os.remove(file_path)
                purged_codes.append(code)
        except Exception:
            continue

    return purged_codes


def switch_to_inherited_mode(code: str, storage_dir: str = DEFAULT_STORAGE_DIR) -> Tuple[str, str, List[str]]:
    """
    Switch a vault record to Inherited Mode:
    - Reads and extracts the stored server Key B and all registered recipient emails.
    - Permanently deletes server Key B AND device_id binding from the file.
    - Sets mode to 'inherited'.
    
    :return: (key_b, encrypted_text, recipients_list)
    :raises ValueError: If code not found or already in inherited mode.
    """
    record = load_vault_record(code, storage_dir)
    if record is None:
        raise ValueError(f"No record found for code '{code}'.")

    if record.get("mode") == "inherited" or record.get("server_key_b") is None:
        raise ValueError(f"Record '{code}' is already in Inherited mode. Server key was already released and deleted.")

    key_b = record["server_key_b"]
    recipients = get_record_recipients(record)

    # Delete server key B AND device_id binding permanently from file
    record["mode"] = "inherited"
    record["server_key_b"] = None
    record["device_id"] = None
    record["inherited_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    file_path = get_file_path(code, storage_dir)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    return key_b, record["encrypted_text"], recipients


def format_duration(seconds: float) -> str:
    """Format seconds into a human-readable duration string (e.g., '29d 23h 59m 10s')."""
    if seconds <= 0:
        return "Expired"
    total_seconds = int(seconds)
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def get_all_vault_statuses(inactivity_days: int = 30, storage_dir: str = DEFAULT_STORAGE_DIR) -> List[Dict]:
    """
    Scan all vault files and return their operational status, including mode,
    deadlines, countdowns, and registered recipient emails.
    """
    ensure_storage_dir(storage_dir)
    statuses = []
    now = datetime.datetime.now(datetime.timezone.utc)

    for filename in os.listdir(storage_dir):
        if not filename.endswith(".json"):
            continue
        file_path = os.path.join(storage_dir, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                record = json.load(f)

            code = record.get("code") or filename[:-5]
            mode = record.get("mode", "normal")
            auto_inherit = record.get("auto_inherit", True)
            rec_inactivity_days = int(record.get("inactivity_days", inactivity_days))
            created_at = record.get("created_at")
            last_active_str = record.get("last_active_at")
            inherited_at = record.get("inherited_at")
            killed_at = record.get("killed_at")
            recipients = get_record_recipients(record)
            has_recipient = len(recipients) > 0

            deadline_iso = None
            seconds_remaining = 0
            time_left_formatted = "—"

            if mode == "normal":
                if last_active_str:
                    inactivity_delta = datetime.timedelta(days=rec_inactivity_days)
                    inactivity_formatted = f"{rec_inactivity_days}d" if rec_inactivity_days == 1 else f"{rec_inactivity_days} Days"
                    clean_ts = last_active_str.replace("Z", "+00:00")
                    last_active = datetime.datetime.fromisoformat(clean_ts)
                    if last_active.tzinfo is None:
                        last_active = last_active.replace(tzinfo=datetime.timezone.utc)
                    deadline = last_active + inactivity_delta
                    deadline_iso = deadline.isoformat()
                    seconds_left = (deadline - now).total_seconds()
                    seconds_remaining = max(0, int(seconds_left))
                    if seconds_left > 0:
                        time_left_formatted = format_duration(seconds_left)
                    else:
                        time_left_formatted = "Expired (Pending Trigger)"
                else:
                    inactivity_formatted = f"{rec_inactivity_days} Days"
                    time_left_formatted = "Unknown"
            else:
                # Inherited or Stopped Mode: 30-Day Final Data Purge Window
                inactivity_formatted = "30d Purge Window"
                ts_str = inherited_at if mode == "inherited" else killed_at
                if ts_str:
                    clean_ts = ts_str.replace("Z", "+00:00")
                    event_time = datetime.datetime.fromisoformat(clean_ts)
                    if event_time.tzinfo is None:
                        event_time = event_time.replace(tzinfo=datetime.timezone.utc)
                    purge_deadline = event_time + datetime.timedelta(days=30)
                    deadline_iso = purge_deadline.isoformat()
                    seconds_left = (purge_deadline - now).total_seconds()
                    seconds_remaining = max(0, int(seconds_left))
                    if seconds_left > 0:
                        time_left_formatted = f"🗑️ Purge in {format_duration(seconds_left)}"
                    else:
                        time_left_formatted = "Expired (Pending Data Purge)"
                else:
                    time_left_formatted = "Triggered (30d Purge Window)"

            statuses.append({
                "code": code,
                "mode": mode,
                "auto_inherit": auto_inherit and rec_inactivity_days > 0,
                "inactivity_days": rec_inactivity_days,
                "inactivity_formatted": inactivity_formatted,
                "created_at": created_at,
                "last_active_at": last_active_str,
                "inherited_at": inherited_at,
                "deadline_at": deadline_iso,
                "seconds_remaining": seconds_remaining,
                "time_left_formatted": time_left_formatted,
                "has_recipient_email": has_recipient,
                "recipient_email": record.get("recipient_email"),
                "recipient_email_2": record.get("recipient_email_2"),
                "recipients": recipients,
            })
        except Exception:
            continue

    # Sort: Normal mode records with closest deadlines first, then infinite/disabled, then Inherited records
    statuses.sort(
        key=lambda x: (
            0 if x["mode"] == "normal" and x.get("auto_inherit") else (1 if x["mode"] == "normal" else 2),
            x["seconds_remaining"] if x["mode"] == "normal" else 0,
            x["code"]
        )
    )
    return statuses


def touch_user_vaults(username: str, storage_dir: str = DEFAULT_STORAGE_DIR) -> int:
    """Update last_active_at timestamp for all normal mode records owned by a user."""
    ensure_storage_dir(storage_dir)
    touched_count = 0
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    clean_user = username.strip().lower()

    for filename in os.listdir(storage_dir):
        if not filename.endswith(".json"):
            continue
        file_path = os.path.join(storage_dir, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                record = json.load(f)

            if record.get("mode") == "normal" and record.get("owner_username", "").lower() == clean_user:
                record["last_active_at"] = now_iso
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(record, f, indent=2)
                touched_count += 1
        except Exception:
            continue

    return touched_count


def get_user_vaults(
    username: str, inactivity_days: int = 30, storage_dir: str = DEFAULT_STORAGE_DIR
) -> List[Dict]:
    """
    Get all vault records owned by a specific user with status and countdown details.
    """
    ensure_storage_dir(storage_dir)
    clean_user = username.strip().lower()
    all_statuses = get_all_vault_statuses(inactivity_days=inactivity_days, storage_dir=storage_dir)
    user_vaults = []

    for status in all_statuses:
        record = load_vault_record(status["code"], storage_dir)
        if record and (record.get("owner_username") or "").lower() == clean_user:
            user_vaults.append({
                **status,
                "owner_username": record.get("owner_username"),
            })

    return user_vaults


