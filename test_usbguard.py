import os
import sqlite3
import tempfile
import unittest

from usb_monitor import DeviceSnapshot, USBMonitor


class USBGuardCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_usbguard.db")
        self.monitor = USBMonitor(db_path=self.db_path, poll_interval=1.0)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_admin_register_and_login(self):
        ok, message = self.monitor.register_admin("adminuser", "secret123")
        self.assertTrue(ok, message)

        duplicate_ok, _ = self.monitor.register_admin("adminuser", "secret123")
        self.assertFalse(duplicate_ok)

        self.assertTrue(self.monitor.authenticate_admin("adminuser", "secret123"))
        self.assertFalse(self.monitor.authenticate_admin("adminuser", "wrongpass"))

    def test_usb_session_logging_and_statistics(self):
        snapshot = DeviceSnapshot(
            key="storage::/tmp/fake",
            device_id="disk2s1",
            device_name="Test USB",
            pnp_device_id="USB\\VID_0781&PID_1234",
            vendor_id="0781",
            mountpoint="/tmp/fake",
        )

        session_id = self.monitor._create_session_log(
            snapshot=snapshot,
            connection_time="2026-04-20 10:00:00",
            threat_level="SAFE",
            unauthorized=False,
            file_count_initial=3,
            activities="Normal operation",
            key_actions="USB_INSERTED",
            status="CONNECTED",
        )

        self.monitor._update_session_log(
            session_id,
            disconnection_time="2026-04-20 10:10:00",
            duration_seconds=600,
            status="DISCONNECTED",
            file_count_final=5,
            files_accessed=2,
            key_actions="USB_INSERTED; USB_REMOVED",
            activities="Normal operation",
        )

        logs = self.monitor.get_recent_usb_logs(limit=5)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["status"], "DISCONNECTED")
        self.assertEqual(logs[0]["file_count_initial"], 3)
        self.assertEqual(logs[0]["file_count_final"], 5)
        self.assertEqual(logs[0]["files_accessed"], 2)

        stats = self.monitor.get_statistics()
        self.assertEqual(stats["total_logs"], 1)
        self.assertEqual(stats["files_accessed"], 2)

    def test_database_migration_from_legacy_schema(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS usb_logs")
        cursor.execute(
            """
            CREATE TABLE usb_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                device_name TEXT,
                vendor_id TEXT,
                product_id TEXT,
                serial_number TEXT,
                connection_time TEXT,
                disconnection_time TEXT,
                duration_seconds INTEGER,
                status TEXT,
                threat_level TEXT,
                activities TEXT
            )
            """
        )
        conn.commit()
        conn.close()

        USBMonitor(db_path=self.db_path)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(usb_logs)")
        columns = {row[1] for row in cursor.fetchall()}
        self.assertIn("session_id", columns)
        self.assertIn("file_count_initial", columns)
        self.assertIn("file_count_final", columns)
        self.assertIn("files_accessed", columns)
        self.assertIn("key_actions", columns)
        conn.close()


if __name__ == "__main__":
    unittest.main()
