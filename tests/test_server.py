"""
Unit and integration tests for 256-Bit Dual-Key Split Crypto, File Attachments, Device Binding, Inactivity Timer, and Inheritance Server.
"""

import base64
import datetime
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import crypto_engine
import email_service
from server import CodeGenRequestHandler, CodeGenServer, process_inactive_vault_records
import storage


class TestCryptoEngine(unittest.TestCase):
    """Unit tests for 256-Bit Dual-Key split crypto functions."""

    def test_256_bit_split_key_generation_and_combination(self):
        key_a, key_b = crypto_engine.generate_split_keys(bits=256)
        self.assertEqual(len(key_a), 44)
        self.assertEqual(len(key_b), 44)
        master_key = crypto_engine.combine_keys(key_a, key_b)
        self.assertEqual(len(master_key), 32)

    def test_256_bit_encrypt_decrypt_roundtrip(self):
        message = "256-bit payload: 🔒 Credentials & Keys"
        res = crypto_engine.encrypt_split(message, key_bits=256)

        self.assertIn("key_a", res)
        self.assertIn("key_b", res)
        self.assertEqual(len(res["key_a"]), 44)
        self.assertEqual(res["key_bits"], 256)

        decrypted = crypto_engine.decrypt_split(res["encrypted_text"], res["key_a"], res["key_b"])
        self.assertEqual(decrypted, message)


class TestEmailService(unittest.TestCase):
    """Unit tests for email dispatch logic."""

    def test_simulation_dispatch(self):
        success, msg = email_service.send_key_b_email("test.recipient@example.com", "Code1234", "KeyB256")
        self.assertTrue(success)
        self.assertIn("Simulation Mode", msg)


class TestServerIntegration(unittest.TestCase):
    """Integration tests running against the active 256-Bit Dual-Key Server."""

    @classmethod
    def setUpClass(cls):
        cls.test_storage_dir = tempfile.mkdtemp()
        cls.server = CodeGenServer(
            ("127.0.0.1", 0),
            CodeGenRequestHandler,
            default_length=16,
            default_charset="alphanumeric",
            default_format="text",
            storage_dir=cls.test_storage_dir,
            key_bits=256,
            inactivity_days=30,
        )
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.test_storage_dir, ignore_errors=True)

    def test_device_binding_flow(self):
        secret = "Secret on Originating Device"
        my_device = "dev_originating_123"
        other_device = "dev_other_456"

        # 1. Encrypt on my_device
        payload = json.dumps({"text": secret, "device_id": my_device, "recipient_email": "test.owner@example.com"}).encode("utf-8")
        req = Request(f"{self.base_url}/api/encrypt", data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            code = data["code"]
            key_a = data["key_a"]

        # 2. Decrypt on my_device (Originating) with only Code + Key A -> SUCCEEDS
        dec_payload = json.dumps({"code": code, "key_a": key_a, "device_id": my_device}).encode("utf-8")
        dec_req = Request(f"{self.base_url}/api/decrypt", data=dec_payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(dec_req) as resp:
            self.assertEqual(resp.status, 200)
            dec_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(dec_data["decrypted_text"], secret)

        # 3. Decrypt on other_device with only Code + Key A -> 400 Bad Request requesting Key B
        other_dec_payload = json.dumps({"code": code, "key_a": key_a, "device_id": other_device}).encode("utf-8")
        other_dec_req = Request(f"{self.base_url}/api/decrypt", data=other_dec_payload, headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(other_dec_req)
        self.assertEqual(ctx.exception.code, 400)

    def test_recipient_email_required_on_encrypt(self):
        """Test that /api/encrypt rejects payloads missing or with invalid recipient email."""
        # 1. Missing email
        payload_no_email = json.dumps({"text": "Test Secret", "device_id": "dev_test"}).encode("utf-8")
        req1 = Request(f"{self.base_url}/api/encrypt", data=payload_no_email, headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req1)
        self.assertEqual(ctx.exception.code, 400)

        # 2. Invalid email format
        payload_bad_email = json.dumps({"text": "Test Secret", "recipient_email": "invalid-email", "device_id": "dev_test"}).encode("utf-8")
        req2 = Request(f"{self.base_url}/api/encrypt", data=payload_bad_email, headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req2)
        self.assertEqual(ctx.exception.code, 400)

    def test_file_attachment_encryption_and_decryption(self):
        """Test attaching, encrypting, and decrypting a binary file payload."""
        sample_file_bytes = b"%PDF-1.4 Mock PDF Content with confidential data \x00\xff\xfe"
        file_b64 = base64.b64encode(sample_file_bytes).decode("utf-8")

        file_payload = {
            "name": "confidential_will.pdf",
            "type": "application/pdf",
            "size": len(sample_file_bytes),
            "data": file_b64,
        }
        text_note = "Please find the attached confidential document."
        device_id = "dev_file_tester"

        # 1. Encrypt text + file
        req_body = json.dumps({
            "text": text_note,
            "file": file_payload,
            "recipient_email": "heir.file@example.com",
            "device_id": device_id,
        }).encode("utf-8")

        req = Request(f"{self.base_url}/api/encrypt", data=req_body, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            code = data["code"]
            key_a = data["key_a"]
            self.assertEqual(len(code), 16)
            self.assertTrue(data["has_file"])

        # Verify on disk that the file content or name does NOT appear in raw text
        vault_file_path = os.path.join(self.test_storage_dir, f"{code}.json")
        with open(vault_file_path, "r", encoding="utf-8") as f:
            disk_content = f.read()
            self.assertNotIn("confidential_will.pdf", disk_content)
            self.assertNotIn("Mock PDF Content", disk_content)

        # 2. Decrypt text + file
        dec_body = json.dumps({
            "code": code,
            "key_a": key_a,
            "device_id": device_id,
        }).encode("utf-8")

        dec_req = Request(f"{self.base_url}/api/decrypt", data=dec_body, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(dec_req) as resp:
            self.assertEqual(resp.status, 200)
            dec_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(dec_data["decrypted_text"], text_note)
            self.assertIsNotNone(dec_data["file"])
            self.assertEqual(dec_data["file"]["name"], "confidential_will.pdf")
            self.assertEqual(dec_data["file"]["type"], "application/pdf")
            
            # Reconstructed binary matches exactly
            decrypted_bytes = base64.b64decode(dec_data["file"]["data"])
            self.assertEqual(decrypted_bytes, sample_file_bytes)

    def test_inactivity_auto_inheritance_trigger(self):
        """Test that records inactive for 30+ days automatically trigger inheritance."""
        code = "INACT001"
        crypto_res = crypto_engine.encrypt_split("Inactive Payload", key_bits=256)
        
        # Save record
        storage.save_vault_record(
            code=code,
            encrypted_text=crypto_res["encrypted_text"],
            server_key_b=crypto_res["key_b"],
            recipient_email="heir@example.com",
            device_id="dev_old_session",
            mode="normal",
            storage_dir=self.test_storage_dir,
        )

        # Backdate the record activity to 32 days ago
        file_path = storage.get_file_path(code, self.test_storage_dir)
        with open(file_path, "r", encoding="utf-8") as f:
            record_data = json.load(f)
        
        past_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=32)
        record_data["last_active_at"] = past_date.isoformat()
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(record_data, f)

        # Verify scanner detects this record
        expired = storage.get_inactive_expired_records(inactivity_days=30, storage_dir=self.test_storage_dir)
        self.assertIn(code, expired)

        # Run automated processing
        processed_count = process_inactive_vault_records(
            storage_dir=self.test_storage_dir,
            inactivity_days=30,
            base_url=self.base_url,
        )
        self.assertGreaterEqual(processed_count, 1)

        # Verify on disk that Key B was purged and mode switched to inherited
        updated_rec = storage.load_vault_record(code, self.test_storage_dir)
        self.assertEqual(updated_rec["mode"], "inherited")
        self.assertIsNone(updated_rec["server_key_b"])
        self.assertIsNone(updated_rec["device_id"])
        self.assertIsNotNone(updated_rec["inherited_at"])


if __name__ == "__main__":
    unittest.main()
