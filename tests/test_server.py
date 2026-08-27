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

        # Register default test account
        reg_payload = json.dumps({"username": "default_user", "password": "DefaultPassword123!"}).encode("utf-8")
        reg_req = Request(f"{cls.base_url}/api/register", data=reg_payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(reg_req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            cls.auth_token = data["token"]
            cls.auth_headers = {"Authorization": f"Bearer {cls.auth_token}"}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.test_storage_dir, ignore_errors=True)

    def test_device_binding_flow(self):
        secret = "Secret on Originating Device"
        my_device = "dev_originating_123"
        other_device = "dev_other_456"

        # 1. Encrypt on my_device (as authenticated user)
        headers = {"Content-Type": "application/json", **self.auth_headers}
        payload = json.dumps({"text": secret, "device_id": my_device, "recipient_email": "test.owner@example.com"}).encode("utf-8")
        req = Request(f"{self.base_url}/api/encrypt", data=payload, headers=headers, method="POST")
        with urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            code = data["code"]
            key_a = data["key_a"]

        # 2. Decrypt as owner with only Code + Key A -> SUCCEEDS
        dec_payload = json.dumps({"code": code, "key_a": key_a}).encode("utf-8")
        dec_req = Request(f"{self.base_url}/api/decrypt", data=dec_payload, headers=headers, method="POST")
        with urlopen(dec_req) as resp:
            self.assertEqual(resp.status, 200)
            dec_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(dec_data["decrypted_text"], secret)

        # 3. Decrypt unauthenticated with only Code + Key A -> 400 Bad Request requesting Key B
        other_dec_payload = json.dumps({"code": code, "key_a": key_a}).encode("utf-8")
        other_dec_req = Request(f"{self.base_url}/api/decrypt", data=other_dec_payload, headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(other_dec_req)
        self.assertEqual(ctx.exception.code, 400)

    def test_recipient_email_required_on_encrypt(self):
        """Test that /api/encrypt rejects payloads missing or with invalid recipient email."""
        headers = {"Content-Type": "application/json", **self.auth_headers}
        # 1. Missing email
        payload_no_email = json.dumps({"text": "Test Secret", "device_id": "dev_test"}).encode("utf-8")
        req1 = Request(f"{self.base_url}/api/encrypt", data=payload_no_email, headers=headers, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req1)
        self.assertEqual(ctx.exception.code, 400)

        # 2. Invalid email format
        payload_bad_email = json.dumps({"text": "Test Secret", "recipient_email": "invalid-email", "device_id": "dev_test"}).encode("utf-8")
        req2 = Request(f"{self.base_url}/api/encrypt", data=payload_bad_email, headers=headers, method="POST")
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
        headers = {"Content-Type": "application/json", **self.auth_headers}
        req_body = json.dumps({
            "text": text_note,
            "file": file_payload,
            "recipient_email": "heir.file@example.com",
            "device_id": device_id,
        }).encode("utf-8")

        req = Request(f"{self.base_url}/api/encrypt", data=req_body, headers=headers, method="POST")
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

        dec_req = Request(f"{self.base_url}/api/decrypt", data=dec_body, headers=headers, method="POST")
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

    def test_stopped_auto_inheritance_avoids_expiry(self):
        """Test stopping auto-inheritance for a record avoids auto-expiry even after 100 days."""
        headers = {"Content-Type": "application/json", **self.auth_headers}
        payload = json.dumps({
            "text": "Secret that gets inheritance stopped",
            "recipient_email": "heir@example.com",
            "device_id": "dev_perm_user"
        }).encode("utf-8")

        req = Request(f"{self.base_url}/api/encrypt", data=payload, headers=headers, method="POST")
        with urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            code = data["code"]
            key_a = data["key_a"]

        # Stop auto-inheritance
        storage.disable_auto_inheritance(code, self.test_storage_dir)

        # Backdate the record by 100 days
        file_path = storage.get_file_path(code, self.test_storage_dir)
        with open(file_path, "r", encoding="utf-8") as f:
            record_data = json.load(f)
        past_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=100)
        record_data["last_active_at"] = past_date.isoformat()
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(record_data, f)

        # Verify scanner does NOT pick up this record
        expired = storage.get_inactive_expired_records(inactivity_days=30, storage_dir=self.test_storage_dir)
        self.assertNotIn(code, expired)

    def test_disable_auto_inheritance_api(self):
        """Test stopping auto-inheritance for an existing record via API."""
        # 1. Create standard record
        headers = {"Content-Type": "application/json", **self.auth_headers}
        payload = json.dumps({
            "text": "Standard secret",
            "recipient_email": "heir@example.com",
            "device_id": "dev_stop_test"
        }).encode("utf-8")
        req = Request(f"{self.base_url}/api/encrypt", data=payload, headers=headers, method="POST")
        with urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            code = data["code"]
            key_a = data["key_a"]

        # 2. Call /api/disable-inheritance with code and key_a
        stop_payload = json.dumps({
            "code": code,
            "key_a": key_a,
            "device_id": "dev_stop_test"
        }).encode("utf-8")
        stop_req = Request(f"{self.base_url}/api/disable-inheritance", data=stop_payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(stop_req) as resp:
            self.assertEqual(resp.status, 200)
            res_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(res_data["status"], "success")
            self.assertFalse(res_data["auto_inherit"])

        # 3. Verify on disk
        rec = storage.load_vault_record(code, self.test_storage_dir)
        self.assertFalse(rec["auto_inherit"])
        self.assertEqual(rec["inactivity_days"], 0)

    def test_inherit_and_disable_require_valid_key_a(self):
        """Test that /api/inherit and /api/disable-inheritance strictly require valid Key A."""
        headers = {"Content-Type": "application/json", **self.auth_headers}
        payload = json.dumps({
            "text": "Strict Key A test secret",
            "recipient_email": "heir.strict@example.com",
        }).encode("utf-8")
        req = Request(f"{self.base_url}/api/encrypt", data=payload, headers=headers, method="POST")
        with urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            code = data["code"]
            key_a = data["key_a"]

        # 1. /api/inherit without key_a -> 400 Bad Request
        no_key_payload = json.dumps({"code": code}).encode("utf-8")
        no_key_req = Request(f"{self.base_url}/api/inherit", data=no_key_payload, headers=headers, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(no_key_req)
        self.assertEqual(ctx.exception.code, 400)

        # 2. /api/inherit with invalid key_a -> 401 Unauthorized
        bad_key_payload = json.dumps({"code": code, "key_a": "invalid_key_a_12345"}).encode("utf-8")
        bad_key_req = Request(f"{self.base_url}/api/inherit", data=bad_key_payload, headers=headers, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(bad_key_req)
        self.assertEqual(ctx.exception.code, 401)

        # 3. /api/disable-inheritance without key_a -> 400 Bad Request
        no_key_stop = json.dumps({"code": code}).encode("utf-8")
        no_key_stop_req = Request(f"{self.base_url}/api/disable-inheritance", data=no_key_stop, headers=headers, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(no_key_stop_req)
        self.assertEqual(ctx.exception.code, 400)

        # 4. /api/disable-inheritance with invalid key_a -> 401 Unauthorized
        bad_key_stop = json.dumps({"code": code, "key_a": "invalid_key_a_12345"}).encode("utf-8")
        bad_key_stop_req = Request(f"{self.base_url}/api/disable-inheritance", data=bad_key_stop, headers=headers, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(bad_key_stop_req)
        self.assertEqual(ctx.exception.code, 401)

        # 5. /api/inherit with valid key_a -> 200 OK
        valid_inherit_payload = json.dumps({"code": code, "key_a": key_a}).encode("utf-8")
        valid_inherit_req = Request(f"{self.base_url}/api/inherit", data=valid_inherit_payload, headers=headers, method="POST")
        with urlopen(valid_inherit_req) as resp:
            self.assertEqual(resp.status, 200)

    def test_purge_expired_inherited_records(self):
        """Test that inherited records older than 30 days are permanently deleted from disk."""
        code = "PURGE001"
        crypto_res = crypto_engine.encrypt_split("Purgeable secret", key_bits=256)
        storage.save_vault_record(
            code=code,
            encrypted_text=crypto_res["encrypted_text"],
            server_key_b=None,
            recipient_email="heir@example.com",
            mode="inherited",
            storage_dir=self.test_storage_dir,
        )

        # Backdate inherited_at to 35 days ago
        file_path = storage.get_file_path(code, self.test_storage_dir)
        with open(file_path, "r", encoding="utf-8") as f:
            rec_data = json.load(f)
        past_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=35)
        rec_data["inherited_at"] = past_date.isoformat()
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(rec_data, f)

        # Run purge
        purged = storage.purge_expired_inherited_records(purge_days=30, storage_dir=self.test_storage_dir)
        self.assertIn(code, purged)
        self.assertFalse(os.path.exists(file_path))

    def test_purge_stopped_deadman_records_after_30_days(self):
        """Test that records where dead man connection was stopped are deleted after 30 days."""
        code = "STOPPURGE01"
        crypto_res = crypto_engine.encrypt_split("Stopped deadman data", key_bits=256)
        storage.save_vault_record(
            code=code,
            encrypted_text=crypto_res["encrypted_text"],
            server_key_b="ServerKeyB",
            recipient_email="heir@example.com",
            mode="normal",
            storage_dir=self.test_storage_dir,
        )

        # Stop dead man connection
        storage.disable_auto_inheritance(code, self.test_storage_dir)

        # Backdate killed_at to 35 days ago
        file_path = storage.get_file_path(code, self.test_storage_dir)
        with open(file_path, "r", encoding="utf-8") as f:
            rec_data = json.load(f)
        self.assertEqual(rec_data["mode"], "stopped")
        past_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=35)
        rec_data["killed_at"] = past_date.isoformat()
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(rec_data, f)

        # Run purge
        purged = storage.purge_expired_inherited_records(purge_days=30, storage_dir=self.test_storage_dir)
        self.assertIn(code, purged)
        self.assertFalse(os.path.exists(file_path))

    def test_user_account_registration_and_authentication(self):
        """Test registering a user, logging in, querying session status, and logging out."""
        username = "alice_test"
        password = "MasterPassword123!"

        # 1. Register
        reg_payload = json.dumps({"username": username, "password": password}).encode("utf-8")
        reg_req = Request(f"{self.base_url}/api/register", data=reg_payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(reg_req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            token = data["token"]
            self.assertEqual(data["username"], username)

        # 2. Check /api/me with Bearer token
        me_req = Request(f"{self.base_url}/api/me", headers={"Authorization": f"Bearer {token}"}, method="GET")
        with urlopen(me_req) as resp:
            self.assertEqual(resp.status, 200)
            me_data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(me_data["authenticated"])
            self.assertEqual(me_data["username"], username)

        # 3. Login with credentials
        login_payload = json.dumps({"username": username, "password": password}).encode("utf-8")
        login_req = Request(f"{self.base_url}/api/login", data=login_payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(login_req) as resp:
            self.assertEqual(resp.status, 200)
            login_data = json.loads(resp.read().decode("utf-8"))
            new_token = login_data["token"]
            self.assertIsNotNone(new_token)

        # 4. Login with wrong password fails
        bad_login_payload = json.dumps({"username": username, "password": "WrongPassword"}).encode("utf-8")
        bad_login_req = Request(f"{self.base_url}/api/login", data=bad_login_payload, headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(bad_login_req)
        self.assertEqual(ctx.exception.code, 401)

        # 5. Logout
        logout_req = Request(f"{self.base_url}/api/logout", headers={"Authorization": f"Bearer {new_token}"}, method="POST")
        with urlopen(logout_req) as resp:
            self.assertEqual(resp.status, 200)

        # 6. Check /api/me after logout
        post_logout_req = Request(f"{self.base_url}/api/me", headers={"Authorization": f"Bearer {new_token}"}, method="GET")
        with urlopen(post_logout_req) as resp:
            post_data = json.loads(resp.read().decode("utf-8"))
            self.assertFalse(post_data["authenticated"])

    def test_account_bound_encryption_and_single_key_owner_decryption(self):
        """Test that an authenticated user encrypts data bound to their account and can decrypt with only Key A."""
        username = "bob_vault_owner"
        password = "SecretPassword456!"

        # Register bob
        reg_payload = json.dumps({"username": username, "password": password}).encode("utf-8")
        reg_req = Request(f"{self.base_url}/api/register", data=reg_payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(reg_req) as resp:
            reg_data = json.loads(resp.read().decode("utf-8"))
            bob_token = reg_data["token"]

        secret_text = "Bob's Top Secret Vault Note"
        
        # 1. Unauthenticated /api/encrypt -> 401 Unauthorized
        unauth_body = json.dumps({"text": secret_text, "recipient_email": "heir@example.com"}).encode("utf-8")
        unauth_req = Request(f"{self.base_url}/api/encrypt", data=unauth_body, headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(unauth_req)
        self.assertEqual(ctx.exception.code, 401)

        # 2. Authenticated /api/encrypt as Bob
        auth_req = Request(
            f"{self.base_url}/api/encrypt",
            data=unauth_body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {bob_token}"},
            method="POST"
        )
        with urlopen(auth_req) as resp:
            self.assertEqual(resp.status, 200)
            enc_data = json.loads(resp.read().decode("utf-8"))
            code = enc_data["code"]
            key_a = enc_data["key_a"]
            self.assertEqual(enc_data["owner_username"], username)

        # 3. Bob queries /api/my-vaults
        vaults_req = Request(
            f"{self.base_url}/api/my-vaults",
            headers={"Authorization": f"Bearer {bob_token}"},
            method="GET"
        )
        with urlopen(vaults_req) as resp:
            self.assertEqual(resp.status, 200)
            vaults_data = json.loads(resp.read().decode("utf-8"))
            self.assertGreaterEqual(vaults_data["count"], 1)
            codes = [v["code"] for v in vaults_data["vaults"]]
            self.assertIn(code, codes)

        # 4. Bob decrypts with ONLY Key A (authenticated as Bob) -> SUCCEEDS
        dec_body = json.dumps({"code": code, "key_a": key_a}).encode("utf-8")
        dec_req = Request(
            f"{self.base_url}/api/decrypt",
            data=dec_body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {bob_token}"},
            method="POST"
        )
        with urlopen(dec_req) as resp:
            self.assertEqual(resp.status, 200)
            dec_res = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(dec_res["decrypted_text"], secret_text)

        # 5. Unauthenticated user decrypts with ONLY Key A -> 400 Bad Request (requires Key B or owner login)
        unauth_dec_req = Request(
            f"{self.base_url}/api/decrypt",
            data=dec_body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with self.assertRaises(HTTPError) as ctx:
            urlopen(unauth_dec_req)
        self.assertEqual(ctx.exception.code, 400)

    def test_delete_vault_api(self):
        """Test deleting a vault permanently from the server via /api/delete-vault."""
        # 1. Register and login test user
        del_user = "user_delete_test"
        reg_payload = json.dumps({"username": del_user, "password": "password123"}).encode("utf-8")
        reg_req = Request(f"{self.base_url}/api/register", data=reg_payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(reg_req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            del_token = data["token"]

        # 2. Encrypt a vault record
        enc_payload = json.dumps({
            "text": "Payload to be deleted permanently",
            "recipient_email": "del.test@example.com"
        }).encode("utf-8")
        enc_req = Request(
            f"{self.base_url}/api/encrypt",
            data=enc_payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {del_token}"},
            method="POST"
        )
        with urlopen(enc_req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            code = data["code"]
            key_a = data["key_a"]

        # Verify file exists on disk
        file_path = os.path.join(self.test_storage_dir, f"{code}.json")
        self.assertTrue(os.path.isfile(file_path))

        # 3. Unauthorized deletion attempt (without token and without key_a) -> 401 Unauthorized
        unauth_del_payload = json.dumps({"code": code}).encode("utf-8")
        unauth_del_req = Request(
            f"{self.base_url}/api/delete-vault",
            data=unauth_del_payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with self.assertRaises(HTTPError) as ctx:
            urlopen(unauth_del_req)
        self.assertEqual(ctx.exception.code, 401)
        self.assertTrue(os.path.isfile(file_path))

        # 4. Authorized deletion as owner -> 200 OK
        auth_del_req = Request(
            f"{self.base_url}/api/delete-vault",
            data=unauth_del_payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {del_token}"},
            method="POST"
        )
        with urlopen(auth_del_req) as resp:
            self.assertEqual(resp.status, 200)
            res_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(res_data["status"], "success")

        # Verify file is permanently deleted from disk
        self.assertFalse(os.path.isfile(file_path))

    def test_persistent_session_file_backed(self):
        """Test that sessions persist to disk and authenticate across requests."""
        # 1. Register persistent test user
        p_user = "persistent_user"
        reg_payload = json.dumps({"username": p_user, "password": "password123"}).encode("utf-8")
        reg_req = Request(f"{self.base_url}/api/register", data=reg_payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(reg_req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            p_token = data["token"]

        # 2. Check that session file exists on disk
        session_file = os.path.join(self.server.sessions_dir, f"{p_token}.json")
        self.assertTrue(os.path.isfile(session_file))

        # 3. Direct query via storage module
        found_user = storage.get_session_username(p_token, self.server.sessions_dir)
        self.assertEqual(found_user, p_user)

        # 4. HTTP query to /api/me with Bearer token
        me_req = Request(f"{self.base_url}/api/me", headers={"Authorization": f"Bearer {p_token}"}, method="GET")
        with urlopen(me_req) as resp:
            me_data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(me_data["authenticated"])
            self.assertEqual(me_data["username"], p_user)

    def test_update_recipient_email_api(self):
        """Test updating the recipient email for a vault record."""
        # 1. Register test user
        upd_user = "user_email_test"
        reg_payload = json.dumps({"username": upd_user, "password": "password123"}).encode("utf-8")
        reg_req = Request(f"{self.base_url}/api/register", data=reg_payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(reg_req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            token = data["token"]

        # 2. Encrypt a vault record with initial recipient
        enc_payload = json.dumps({
            "text": "Secret with initial recipient",
            "recipient_email": "initial.heir@example.com"
        }).encode("utf-8")
        enc_req = Request(
            f"{self.base_url}/api/encrypt",
            data=enc_payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST"
        )
        with urlopen(enc_req) as resp:
            enc_data = json.loads(resp.read().decode("utf-8"))
            code = enc_data["code"]
            key_a = enc_data["key_a"]

        # Verify initial recipient in record
        rec = storage.load_vault_record(code, self.test_storage_dir)
        self.assertEqual(rec["recipient_email"], "initial.heir@example.com")

        # 3. Unauthorized update attempt without credentials -> 401
        unauth_payload = json.dumps({"code": code, "email": "hacked@example.com"}).encode("utf-8")
        unauth_req = Request(f"{self.base_url}/api/update-recipient", data=unauth_payload, headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(unauth_req)
        self.assertEqual(ctx.exception.code, 401)

        # 4. Update with invalid email -> 400
        bad_email_payload = json.dumps({"code": code, "email": "invalid-email"}).encode("utf-8")
        bad_req = Request(
            f"{self.base_url}/api/update-recipient",
            data=bad_email_payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST"
        )
        with self.assertRaises(HTTPError) as ctx:
            urlopen(bad_req)
        self.assertEqual(ctx.exception.code, 400)

        # 5. Authorized update as owner -> 200 OK
        new_email = "new.heir2026@example.ch"
        upd_payload = json.dumps({"code": code, "email": new_email}).encode("utf-8")
        upd_req = Request(
            f"{self.base_url}/api/update-recipient",
            data=upd_payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST"
        )
        with urlopen(upd_req) as resp:
            self.assertEqual(resp.status, 200)
            res_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(res_data["status"], "success")
            self.assertEqual(res_data["recipient_email"], new_email)

        # Verify record updated on disk
        updated_rec = storage.load_vault_record(code, self.test_storage_dir)
        self.assertEqual(updated_rec["recipient_email"], new_email)

        # 6. Verify in /api/my-vaults
        vaults_req = Request(f"{self.base_url}/api/my-vaults", headers={"Authorization": f"Bearer {token}"}, method="GET")
        with urlopen(vaults_req) as resp:
            v_data = json.loads(resp.read().decode("utf-8"))
            user_vault = next(v for v in v_data["vaults"] if v["code"] == code)
            self.assertEqual(user_vault["recipient_email"], new_email)


if __name__ == "__main__":
    unittest.main()



