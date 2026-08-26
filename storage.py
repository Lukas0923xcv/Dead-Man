"""
File-based storage engine for Dual-Key split encrypted records.
Stores vault records under unique 8-character reference codes with device binding,
last activity tracking, and Normal/Inherited mode support.
"""

import datetime
import json
import os
import re
from typing import Dict, List, Optional, Tuple

DEFAULT_STORAGE_DIR = os.getenv("STORAGE_DIR", os.path.join(os.path.dirname(__file__), "data", "vault"))

# Strict validator for 8-character alphanumeric codes
CODE_PATTERN = re.compile(r"^[a-zA-Z0-9]{8}$")


def ensure_storage_dir(storage_dir: str = DEFAULT_STORAGE_DIR) -> str:
    """Ensure that the storage directory exists and return its path."""
    os.makedirs(storage_dir, exist_ok=True)
    return storage_dir


def validate_code(code: str) -> bool:
    """Check if the provided code is a valid 8-character alphanumeric identifier."""
    if not isinstance(code, str):
        return False
    return bool(CODE_PATTERN.match(code.strip()))


def get_file_path(code: str, storage_dir: str = DEFAULT_STORAGE_DIR) -> str:
    """Get the sanitized absolute JSON file path for a code."""
    clean_code = code.strip()
    if not validate_code(clean_code):
        raise ValueError(f"Invalid code format '{code}'. Must be an 8-character alphanumeric string.")
    return os.path.join(storage_dir, f"{clean_code}.json")


def code_exists(code: str, storage_dir: str = DEFAULT_STORAGE_DIR) -> bool:
    """Check if an encrypted vault record exists for the given 8-character code."""
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
    device_id: Optional[str] = None,
    mode: str = "normal",
    storage_dir: str = DEFAULT_STORAGE_DIR,
) -> str:
    """
    Save a new vault record with ciphertext, server key (Key B), recipient email,
    device binding ID, and initial activity timestamp.
    """
    ensure_storage_dir(storage_dir)
    file_path = get_file_path(code, storage_dir)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    record = {
        "code": code,
        "mode": mode,
        "encrypted_text": encrypted_text.strip(),
        "server_key_b": server_key_b,
        "device_id": device_id.strip() if device_id else None,
        "recipient_email": recipient_email.strip() if recipient_email else None,
        "created_at": now_iso,
        "last_active_at": now_iso,
        "inherited_at": None,
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
    """
    ensure_storage_dir(storage_dir)
    expired_codes = []
    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff_delta = datetime.timedelta(days=inactivity_days)

    for filename in os.listdir(storage_dir):
        if not filename.endswith(".json"):
            continue
        file_path = os.path.join(storage_dir, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                record = json.load(f)

            if record.get("mode") != "normal" or not record.get("server_key_b"):
                continue

            last_active_str = record.get("last_active_at") or record.get("created_at")
            if not last_active_str:
                continue

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


def switch_to_inherited_mode(code: str, storage_dir: str = DEFAULT_STORAGE_DIR) -> Tuple[str, str, Optional[str]]:
    """
    Switch a vault record to Inherited Mode:
    - Reads and extracts the stored server Key B and recipient email.
    - Permanently deletes server Key B AND device_id binding from the file.
    - Sets mode to 'inherited'.
    
    :return: (key_b, encrypted_text, recipient_email)
    :raises ValueError: If code not found or already in inherited mode.
    """
    record = load_vault_record(code, storage_dir)
    if record is None:
        raise ValueError(f"No record found for code '{code}'.")

    if record.get("mode") == "inherited" or record.get("server_key_b") is None:
        raise ValueError(f"Record '{code}' is already in Inherited mode. Server key was already released and deleted.")

    key_b = record["server_key_b"]
    recipient_email = record.get("recipient_email")

    # Delete server key B AND device_id binding permanently from file
    record["mode"] = "inherited"
    record["server_key_b"] = None
    record["device_id"] = None
    record["inherited_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    file_path = get_file_path(code, storage_dir)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    return key_b, record["encrypted_text"], recipient_email


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


def get_all_vault_statuses(
    inactivity_days: int = 30, storage_dir: str = DEFAULT_STORAGE_DIR
) -> List[Dict]:
    """
    Scan all vault records and return a sanitized list of statuses for monitoring.
    Contains code, mode, time remaining, and timestamps without leaking ciphertext or keys.
    """
    ensure_storage_dir(storage_dir)
    statuses = []
    now = datetime.datetime.now(datetime.timezone.utc)
    inactivity_delta = datetime.timedelta(days=inactivity_days)

    for filename in sorted(os.listdir(storage_dir)):
        if not filename.endswith(".json"):
            continue
        file_path = os.path.join(storage_dir, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                record = json.load(f)

            code = record.get("code") or filename[:-5]
            mode = record.get("mode", "normal")
            created_at = record.get("created_at")
            last_active_str = record.get("last_active_at") or created_at
            inherited_at = record.get("inherited_at")
            has_recipient = bool(record.get("recipient_email"))

            seconds_remaining = 0
            time_left_formatted = "N/A"
            deadline_iso = None

            if mode == "normal":
                if last_active_str:
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
                    time_left_formatted = "Unknown"
            else:
                time_left_formatted = "Triggered (Inherited)"

            statuses.append({
                "code": code,
                "mode": mode,
                "created_at": created_at,
                "last_active_at": last_active_str,
                "inherited_at": inherited_at,
                "deadline_at": deadline_iso,
                "inactivity_days": inactivity_days,
                "seconds_remaining": seconds_remaining,
                "time_left_formatted": time_left_formatted,
                "has_recipient_email": has_recipient,
            })
        except Exception:
            continue

    # Sort: Normal mode records with closest deadlines first, then Inherited records
    statuses.sort(
        key=lambda x: (
            0 if x["mode"] == "normal" else 1,
            x["seconds_remaining"] if x["mode"] == "normal" else 0,
            x["code"]
        )
    )
    return statuses

