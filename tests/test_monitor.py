"""
Unit and integration tests for the Dead Man's Switch Monitor Website.
"""

import datetime
import json
import os
import shutil
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen

import monitor_server
import storage


class TestMonitorStorage(unittest.TestCase):
    """Test status calculation and metadata extraction from storage."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_get_all_vault_statuses_normal_and_inherited(self):
        # 1. Normal record
        storage.save_vault_record(
            code="NORM1234",
            encrypted_text="Ciphertext1",
            server_key_b="KeyBSecret1",
            recipient_email="heir@example.com",
            device_id="dev-123",
            mode="normal",
            storage_dir=self.test_dir,
        )

        # 2. Inherited record
        storage.save_vault_record(
            code="INHT5678",
            encrypted_text="Ciphertext2",
            server_key_b="KeyBSecret2",
            recipient_email="heir2@example.com",
            device_id="dev-456",
            mode="normal",
            storage_dir=self.test_dir,
        )
        storage.switch_to_inherited_mode("INHT5678", self.test_dir)

        statuses = storage.get_all_vault_statuses(inactivity_days=30, storage_dir=self.test_dir)
        self.assertEqual(len(statuses), 2)

        norm_status = next(s for s in statuses if s["code"] == "NORM1234")
        self.assertEqual(norm_status["mode"], "normal")
        self.assertGreater(norm_status["seconds_remaining"], 0)
        self.assertIn("d", norm_status["time_left_formatted"])
        self.assertNotIn("server_key_b", norm_status)
        self.assertNotIn("encrypted_text", norm_status)
        self.assertTrue(norm_status["has_recipient_email"])
        self.assertGreater(norm_status["file_size_bytes"], 0)
        self.assertIn("B", norm_status["file_size_formatted"])

        inht_status = next(s for s in statuses if s["code"] == "INHT5678")
        self.assertEqual(inht_status["mode"], "inherited")
        self.assertIn("Purge", inht_status["time_left_formatted"])
        self.assertGreater(inht_status["seconds_remaining"], 0)
        self.assertGreater(inht_status["file_size_bytes"], 0)

        # Test storage statistics helper
        stats = storage.get_storage_stats(storage_dir=self.test_dir)
        self.assertEqual(stats["total_files"], 2)
        self.assertGreater(stats["total_bytes"], 0)
        self.assertIn("B", stats["total_size_formatted"])


class TestMonitorServerIntegration(unittest.TestCase):
    """Integration test for the monitor HTTP web server on ephemeral port."""

    @classmethod
    def setUpClass(cls):
        cls.test_dir = tempfile.mkdtemp()
        storage.save_vault_record(
            code="CODE9999",
            encrypted_text="SecretCipher",
            server_key_b="SecretKeyB",
            recipient_email="notify@example.com",
            device_id="dev-999",
            mode="normal",
            storage_dir=cls.test_dir,
        )

        cls.server = monitor_server.MonitorServer(
            ("127.0.0.1", 0),
            monitor_server.MonitorRequestHandler,
            storage_dir=cls.test_dir,
            inactivity_days=30,
        )
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def test_dashboard_html_page(self):
        url = f"http://127.0.0.1:{self.port}/"
        with urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            content = resp.read().decode("utf-8")
            self.assertIn("SecureVault Monitor", content)
            self.assertIn("Dead Man's Switch Status Dashboard", content)
            self.assertIn("Total Storage Used", content)
            self.assertIn("File Size", content)

    def test_api_status_json_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/api/status"
        with urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["total_count"], 1)
            self.assertEqual(data["normal_count"], 1)
            self.assertEqual(data["inherited_count"], 0)
            self.assertGreater(data["total_storage_bytes"], 0)
            self.assertIn("B", data["total_storage_formatted"])
            self.assertEqual(len(data["records"]), 1)
            self.assertEqual(data["records"][0]["code"], "CODE9999")
            self.assertEqual(data["records"][0]["mode"], "normal")
            self.assertGreater(data["records"][0]["file_size_bytes"], 0)
            self.assertIn("B", data["records"][0]["file_size_formatted"])

    def test_health_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/health"
        with urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "healthy")


if __name__ == "__main__":
    unittest.main()
