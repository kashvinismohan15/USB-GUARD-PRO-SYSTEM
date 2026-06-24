"""USBGuard Pro core monitoring and SQL services."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover
    psutil = None

try:
    import wmi  # type: ignore
except ImportError:  # pragma: no cover
    wmi = None

THREAT_ORDER = {
    "SAFE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass
class DeviceSnapshot:
    key: str
    device_id: str
    device_name: str
    pnp_device_id: str
    vendor_id: Optional[str]
    mountpoint: Optional[str] = None


class USBMonitor:
    def __init__(
        self,
        db_path: str = "usb_logs.db",
        poll_interval: float = 2.0,
        auto_block: bool = False,
        max_connection_seconds: int = 900,
        file_spike_threshold: int = 25,
    ) -> None:
        self.db_path = db_path
        self.poll_interval = max(1.0, float(poll_interval))
        self.auto_block = bool(auto_block)
        self.max_connection_seconds = max(60, int(max_connection_seconds))
        self.file_spike_threshold = max(5, int(file_spike_threshold))

        self.active_devices: Dict[str, Dict[str, Any]] = {}
        self.blocked_devices: set[str] = set()

        self._monitoring = False
        self._stop_event = threading.Event()

        self.c = None
        if os.name == "nt" and wmi is not None:
            try:
                self.c = wmi.WMI()
            except Exception:
                self.c = None

        self.init_database()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _now_str() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def init_database(self) -> None:
        """Initialize and migrate SQLite schema."""
        with self._connect() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_login TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS usb_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    device_id TEXT,
                    device_name TEXT,
                    vendor_id TEXT,
                    product_id TEXT,
                    serial_number TEXT,
                    mountpoint TEXT,
                    connection_time TEXT,
                    disconnection_time TEXT,
                    duration_seconds INTEGER,
                    status TEXT,
                    threat_level TEXT,
                    unauthorized INTEGER DEFAULT 0,
                    file_count_initial INTEGER DEFAULT 0,
                    file_count_final INTEGER DEFAULT 0,
                    files_accessed INTEGER DEFAULT 0,
                    key_actions TEXT,
                    activities TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT,
                    detection_time TEXT,
                    threat_type TEXT,
                    description TEXT,
                    action_taken TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS system_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_time TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    device_id TEXT,
                    device_name TEXT,
                    details TEXT
                )
                """
            )

            self._ensure_column(cursor, "usb_logs", "session_id", "TEXT")
            self._ensure_column(cursor, "usb_logs", "mountpoint", "TEXT")
            self._ensure_column(cursor, "usb_logs", "unauthorized", "INTEGER DEFAULT 0")
            self._ensure_column(cursor, "usb_logs", "file_count_initial", "INTEGER DEFAULT 0")
            self._ensure_column(cursor, "usb_logs", "file_count_final", "INTEGER DEFAULT 0")
            self._ensure_column(cursor, "usb_logs", "files_accessed", "INTEGER DEFAULT 0")
            self._ensure_column(cursor, "usb_logs", "key_actions", "TEXT")
            self._ensure_unique_index(
                cursor,
                "idx_usb_logs_session_id_unique",
                "usb_logs",
                "session_id",
            )

            conn.commit()

    @staticmethod
    def _ensure_column(cursor: sqlite3.Cursor, table: str, column: str, definition: str) -> None:
        columns = [row[1] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()]
        if column not in columns:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    @staticmethod
    def _ensure_unique_index(
        cursor: sqlite3.Cursor,
        index_name: str,
        table: str,
        column: str,
    ) -> None:
        cursor.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS {index_name} ON {table} ({column})")

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            180_000,
        )
        return digest.hex()

    def admin_exists(self) -> bool:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS c FROM admins")
            return int(cursor.fetchone()["c"]) > 0

    def register_admin(self, username: str, password: str) -> Tuple[bool, str]:
        username = (username or "").strip()
        if len(username) < 3:
            return False, "Username must be at least 3 characters."
        if len(password or "") < 6:
            return False, "Password must be at least 6 characters."

        salt = secrets.token_hex(16)
        password_hash = self._hash_password(password, salt)

        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO admins (username, password_hash, salt, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, password_hash, salt, self._now_str()),
                )
                conn.commit()
            return True, "Admin registration successful."
        except sqlite3.IntegrityError:
            return False, "Username already exists."

    def authenticate_admin(self, username: str, password: str) -> bool:
        username = (username or "").strip()
        if not username or not password:
            return False

        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, password_hash, salt FROM admins WHERE username = ?",
                (username,),
            )
            row = cursor.fetchone()
            if row is None:
                return False

            expected_hash = row["password_hash"]
            current_hash = self._hash_password(password, row["salt"])
            if not hmac.compare_digest(expected_hash, current_hash):
                return False

            cursor.execute(
                "UPDATE admins SET last_login = ? WHERE id = ?",
                (self._now_str(), row["id"]),
            )
            conn.commit()
        return True

    @staticmethod
    def extract_vendor_id(pnp_device_id: str) -> Optional[str]:
        pnp = (pnp_device_id or "").upper()
        if "VID_" in pnp:
            idx = pnp.find("VID_") + 4
            vendor_id = pnp[idx : idx + 4]
            if len(vendor_id) == 4:
                return vendor_id
        return None

    @staticmethod
    def is_trusted_vendor(vendor_id: str) -> bool:
        trusted = {
            "0781",  # SanDisk
            "0951",  # Kingston
            "058F",  # Alcor
            "090C",  # Silicon Motion
            "8564",  # Transcend
            "13FE",  # Kingston alt
            "046D",  # Logitech
            "045E",  # Microsoft
            "05AC",  # Apple
        }
        return (vendor_id or "").upper() in trusted

    @staticmethod
    def _is_removable_partition(partition: Any) -> bool:
        opts = (getattr(partition, "opts", "") or "").lower()
        mountpoint = (getattr(partition, "mountpoint", "") or "").lower()
        if "removable" in opts:
            return True
        return mountpoint.startswith("/volumes") or mountpoint.startswith("/media") or mountpoint.startswith("/run/media")

    def _discover_storage_devices(self) -> Dict[str, DeviceSnapshot]:
        devices: Dict[str, DeviceSnapshot] = {}
        if psutil is None:
            return devices

        try:
            for partition in psutil.disk_partitions(all=False):
                if not self._is_removable_partition(partition):
                    continue
                mountpoint = getattr(partition, "mountpoint", "")
                device_id = getattr(partition, "device", "") or mountpoint
                pnp_id = device_id
                key = f"storage::{mountpoint}"
                devices[key] = DeviceSnapshot(
                    key=key,
                    device_id=device_id,
                    device_name=f"Removable Storage ({mountpoint})",
                    pnp_device_id=pnp_id,
                    vendor_id=self.extract_vendor_id(pnp_id),
                    mountpoint=mountpoint,
                )
        except Exception:
            return {}

        return devices

    def _discover_windows_usb_devices(self) -> Dict[str, DeviceSnapshot]:
        devices: Dict[str, DeviceSnapshot] = {}
        if self.c is None:
            return devices

        try:
            for dev in self.c.Win32_USBHub():
                device_id = str(getattr(dev, "DeviceID", "") or "")
                pnp_id = str(getattr(dev, "PNPDeviceID", "") or "")
                name = str(getattr(dev, "Caption", "Unknown USB Device") or "Unknown USB Device")
                key = f"hub::{device_id}"
                devices[key] = DeviceSnapshot(
                    key=key,
                    device_id=device_id,
                    device_name=name,
                    pnp_device_id=pnp_id,
                    vendor_id=self.extract_vendor_id(pnp_id),
                )
        except Exception:
            return {}

        return devices

    def _discover_devices(self) -> Dict[str, DeviceSnapshot]:
        devices = self._discover_windows_usb_devices()
        devices.update(self._discover_storage_devices())
        return devices

    @staticmethod
    def _device_fingerprint(snapshot: DeviceSnapshot) -> str:
        payload = f"{snapshot.device_id}|{snapshot.pnp_device_id}|{snapshot.mountpoint or ''}"
        return hashlib.md5(payload.encode("utf-8")).hexdigest()

    def check_autorun_files(self, mountpoint: Optional[str]) -> bool:
        if not mountpoint:
            return False
        try:
            return os.path.exists(os.path.join(mountpoint, "autorun.inf"))
        except Exception:
            return False

    def detect_malicious_activity(self, snapshot: DeviceSnapshot) -> Tuple[List[str], str, bool]:
        threats: List[str] = []
        threat_level = "SAFE"
        unauthorized = False

        def bump_level(level: str) -> None:
            nonlocal threat_level
            if THREAT_ORDER[level] > THREAT_ORDER[threat_level]:
                threat_level = level

        pnp = (snapshot.pnp_device_id or "").upper()
        name = (snapshot.device_name or "").upper()

        if "HID" in pnp and not any(x in name for x in ("KEYBOARD", "MOUSE", "TRACKPAD", "GAME")):
            threats.append("Suspicious HID profile detected")
            bump_level("HIGH")
            unauthorized = True

        if snapshot.vendor_id and not self.is_trusted_vendor(snapshot.vendor_id):
            threats.append(f"Unknown vendor ID: {snapshot.vendor_id}")
            bump_level("LOW")
            unauthorized = True

        if self.check_autorun_files(snapshot.mountpoint):
            threats.append("autorun.inf detected on removable media")
            bump_level("MEDIUM")
            unauthorized = True

        if self._device_fingerprint(snapshot) in self.blocked_devices:
            threats.append("Previously blocked USB attempting reconnection")
            bump_level("CRITICAL")
            unauthorized = True

        return threats, threat_level, unauthorized

    def _collect_file_stats(self, mountpoint: Optional[str], max_files: int = 20000) -> Tuple[int, Dict[str, float]]:
        if not mountpoint or not os.path.exists(mountpoint):
            return 0, {}

        file_count = 0
        access_map: Dict[str, float] = {}

        try:
            for root, _, files in os.walk(mountpoint):
                for file_name in files:
                    path = os.path.join(root, file_name)
                    try:
                        st = os.stat(path)
                    except (PermissionError, OSError):
                        continue
                    file_count += 1
                    access_map[path] = st.st_atime
                    if file_count >= max_files:
                        return file_count, access_map
        except (PermissionError, OSError):
            return file_count, access_map

        return file_count, access_map

    @staticmethod
    def _estimate_files_accessed(previous: Dict[str, float], current: Dict[str, float]) -> int:
        opened = 0
        for path, prev_atime in previous.items():
            current_atime = current.get(path)
            if current_atime is not None and current_atime > prev_atime + 0.5:
                opened += 1

        new_files = len(set(current.keys()) - set(previous.keys()))
        return opened + max(0, new_files)

    def _log_threat(self, snapshot: DeviceSnapshot, threat_type: str, description: str, action_taken: str) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO threat_detections
                (device_id, detection_time, threat_type, description, action_taken)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    snapshot.device_id,
                    self._now_str(),
                    threat_type,
                    description,
                    action_taken,
                ),
            )
            conn.commit()

    def _log_system_event(self, event_type: str, snapshot: Optional[DeviceSnapshot], details: str) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO system_events (event_time, event_type, device_id, device_name, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    self._now_str(),
                    event_type,
                    snapshot.device_id if snapshot else None,
                    snapshot.device_name if snapshot else None,
                    details,
                ),
            )
            conn.commit()

    def _create_session_log(
        self,
        snapshot: DeviceSnapshot,
        connection_time: str,
        threat_level: str,
        unauthorized: bool,
        file_count_initial: int,
        activities: str,
        key_actions: str,
        status: str = "CONNECTED",
    ) -> str:
        session_id = str(uuid.uuid4())
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO usb_logs (
                    session_id, device_id, device_name, vendor_id, product_id,
                    serial_number, mountpoint, connection_time, status, threat_level,
                    unauthorized, file_count_initial, file_count_final, files_accessed,
                    key_actions, activities
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    snapshot.device_id,
                    snapshot.device_name,
                    snapshot.vendor_id,
                    "N/A",
                    "N/A",
                    snapshot.mountpoint,
                    connection_time,
                    status,
                    threat_level,
                    int(unauthorized),
                    int(file_count_initial),
                    int(file_count_initial),
                    0,
                    key_actions,
                    activities,
                ),
            )
            conn.commit()
        return session_id

    def _update_session_log(self, session_id: str, **fields: Any) -> None:
        if not session_id or not fields:
            return

        allowed = {
            "disconnection_time",
            "duration_seconds",
            "status",
            "threat_level",
            "file_count_final",
            "files_accessed",
            "key_actions",
            "activities",
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [session_id]

        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE usb_logs SET {set_clause} WHERE session_id = ?", params)
            conn.commit()

    def get_recent_usb_logs(self, limit: int = 200) -> List[sqlite3.Row]:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, session_id, device_name, vendor_id, mountpoint, connection_time,
                       disconnection_time, duration_seconds, status, threat_level,
                       unauthorized, file_count_initial, file_count_final, files_accessed,
                       key_actions, activities
                FROM usb_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(limit),),
            )
            return cursor.fetchall()

    def get_recent_threats(self, limit: int = 200) -> List[sqlite3.Row]:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, device_id, detection_time, threat_type, description, action_taken
                FROM threat_detections
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(limit),),
            )
            return cursor.fetchall()

    def get_recent_system_events(self, limit: int = 200) -> List[sqlite3.Row]:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, event_time, event_type, device_name, details
                FROM system_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(limit),),
            )
            return cursor.fetchall()

    def get_statistics(self) -> Dict[str, Any]:
        with self._connect() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) AS v FROM usb_logs")
            total_logs = int(cursor.fetchone()["v"])

            cursor.execute("SELECT COUNT(*) AS v FROM threat_detections")
            total_threats = int(cursor.fetchone()["v"])

            cursor.execute("SELECT COUNT(*) AS v FROM usb_logs WHERE status LIKE 'BLOCKED%'")
            blocked = int(cursor.fetchone()["v"])

            cursor.execute("SELECT COUNT(*) AS v FROM usb_logs WHERE threat_level = 'SAFE'")
            safe = int(cursor.fetchone()["v"])

            cursor.execute("SELECT AVG(duration_seconds) AS v FROM usb_logs WHERE duration_seconds IS NOT NULL")
            avg_duration = cursor.fetchone()["v"]

            cursor.execute("SELECT SUM(files_accessed) AS v FROM usb_logs")
            files_accessed = cursor.fetchone()["v"] or 0

        return {
            "total_logs": total_logs,
            "total_threats": total_threats,
            "blocked": blocked,
            "safe": safe,
            "avg_duration": int(avg_duration) if avg_duration else 0,
            "files_accessed": int(files_accessed),
            "active_devices": len(self.active_devices),
        }

    def stop_monitoring(self) -> None:
        self._monitoring = False
        self._stop_event.set()

    def block_device(self, snapshot: DeviceSnapshot, reason: str = "Manual block", manual: bool = True) -> bool:
        self.blocked_devices.add(self._device_fingerprint(snapshot))

        if self.c is not None and snapshot.device_id:
            escaped_id = snapshot.device_id.replace("\\", "\\\\")
            query = f"SELECT * FROM Win32_PnPEntity WHERE DeviceID='{escaped_id}'"
            try:
                for dev in self.c.query(query):
                    disable = getattr(dev, "Disable", None)
                    if callable(disable):
                        disable()
            except Exception:
                pass

        active = self.active_devices.get(snapshot.key)
        if active:
            active["status"] = "BLOCKED_MANUAL" if manual else "BLOCKED_AUTO"
            active["blocked"] = True
            active["threat_level"] = "CRITICAL"
            action = "MANUAL_BLOCK" if manual else "AUTO_BLOCK"
            active["key_actions"].append(action)
            active["activities"].append(reason)
            self._update_session_log(
                active["session_id"],
                status=active["status"],
                threat_level="CRITICAL",
                key_actions="; ".join(active["key_actions"]),
                activities="; ".join(active["activities"]),
            )

        self._log_system_event("DEVICE_BLOCKED", snapshot, reason)
        self._log_threat(snapshot, "HIGH", reason, "BLOCKED")
        return True

    def block_device_by_key(self, device_key: str, reason: str = "Manual block") -> bool:
        active = self.active_devices.get(device_key)
        if active is None:
            return False
        return self.block_device(active["snapshot"], reason=reason, manual=True)

    def _handle_connected_device(
        self,
        snapshot: DeviceSnapshot,
        callback: Optional[Callable[[str, DeviceSnapshot, List[str], str, bool, str], None]],
    ) -> None:
        connection_time = self._now_str()
        threats, threat_level, unauthorized = self.detect_malicious_activity(snapshot)
        initial_count, access_map = self._collect_file_stats(snapshot.mountpoint)

        activities = threats[:] if threats else ["Normal operation"]
        key_actions = ["USB_INSERTED"]
        session_id = self._create_session_log(
            snapshot=snapshot,
            connection_time=connection_time,
            threat_level=threat_level,
            unauthorized=unauthorized,
            file_count_initial=initial_count,
            activities="; ".join(activities),
            key_actions="; ".join(key_actions),
            status="CONNECTED",
        )

        self.active_devices[snapshot.key] = {
            "snapshot": snapshot,
            "session_id": session_id,
            "connected_epoch": time.time(),
            "threat_level": threat_level,
            "unauthorized": unauthorized,
            "status": "CONNECTED",
            "blocked": False,
            "initial_file_count": initial_count,
            "last_file_count": initial_count,
            "baseline_access_map": access_map,
            "last_access_map": access_map,
            "files_accessed": 0,
            "last_reported_files_accessed": 0,
            "transfer_notify_at": 0.0,
            "time_alerted": False,
            "spike_alerted": False,
            "key_actions": key_actions,
            "activities": activities,
            "last_db_update": 0.0,
        }

        self._log_system_event(
            "USB_INSERTED",
            snapshot,
            f"Inserted. Threat={threat_level}, unauthorized={unauthorized}",
        )

        for threat in threats:
            self._log_threat(snapshot, threat_level, threat, "ALERTED")

        if callback:
            callback("connected", snapshot, threats, threat_level, unauthorized, "CONNECTED")

        if unauthorized and callback:
            callback("alert", snapshot, threats or ["Unauthorized USB detected"], threat_level, True, "ALERTED")

        if self.auto_block and (unauthorized or threat_level in {"HIGH", "CRITICAL"}):
            self.block_device(snapshot, reason="Auto policy block", manual=False)
            if callback:
                callback("alert", snapshot, ["Device auto-blocked by policy"], "CRITICAL", True, "BLOCKED_AUTO")

    def _refresh_active_device(
        self,
        info: Dict[str, Any],
        callback: Optional[Callable[[str, DeviceSnapshot, List[str], str, bool, str], None]],
    ) -> None:
        snapshot = info["snapshot"]

        if snapshot.mountpoint:
            file_count, access_map = self._collect_file_stats(snapshot.mountpoint)
            info["last_file_count"] = file_count
            info["files_accessed"] = max(
                int(info["files_accessed"]),
                self._estimate_files_accessed(info["baseline_access_map"], access_map),
            )
            info["last_access_map"] = access_map

            files_accessed_now = int(info["files_accessed"])
            last_reported = int(info["last_reported_files_accessed"])
            transfer_cooldown = 30.0
            now_epoch = time.time()
            if files_accessed_now > last_reported and (now_epoch - float(info["transfer_notify_at"])) >= transfer_cooldown:
                new_count = files_accessed_now - last_reported
                info["last_reported_files_accessed"] = files_accessed_now
                info["transfer_notify_at"] = now_epoch
                info["activities"].append(f"File transfer detected ({new_count} files)")
                info["key_actions"].append("FILE_TRANSFER")
                self._log_system_event("FILE_TRANSFER", snapshot, f"Files accessed from USB: {new_count}")
                self._log_threat(snapshot, "LOW", f"File transfer detected: {new_count} file(s) accessed", "ALERTED")
                if callback:
                    callback(
                        "transfer_detected",
                        snapshot,
                        [f"{new_count} file(s) accessed/transferred from USB"],
                        info["threat_level"],
                        False,
                        "ALERTED",
                    )

            delta = abs(file_count - int(info["initial_file_count"]))
            if delta >= self.file_spike_threshold and not info["spike_alerted"]:
                info["spike_alerted"] = True
                info["activities"].append(f"File count spike ({delta})")
                info["key_actions"].append("FILE_COUNT_SPIKE")
                self._log_system_event("FILE_COUNT_SPIKE", snapshot, f"Delta={delta}")
                self._log_threat(snapshot, "MEDIUM", f"File count spike: {delta}", "ALERTED")
                if callback:
                    callback(
                        "alert",
                        snapshot,
                        [f"File count changed rapidly: {delta}"],
                        "MEDIUM",
                        True,
                        "ALERTED",
                    )

        elapsed = int(time.time() - info["connected_epoch"])
        if elapsed >= self.max_connection_seconds and not info["time_alerted"]:
            info["time_alerted"] = True
            info["activities"].append("Time threshold alert")
            info["key_actions"].append("TIME_THRESHOLD_ALERT")
            self._log_system_event("TIME_THRESHOLD_ALERT", snapshot, f"Connected for {elapsed} seconds")
            self._log_threat(
                snapshot,
                "MEDIUM",
                f"Connected more than {self.max_connection_seconds} seconds",
                "ALERTED",
            )
            if callback:
                callback(
                    "alert",
                    snapshot,
                    [f"USB connected too long ({elapsed} seconds)"],
                    "MEDIUM",
                    True,
                    "ALERTED",
                )

        now_epoch = time.time()
        if now_epoch - float(info["last_db_update"]) >= 10:
            info["last_db_update"] = now_epoch
            self._update_session_log(
                info["session_id"],
                status=info["status"],
                file_count_final=int(info["last_file_count"]),
                files_accessed=int(info["files_accessed"]),
                key_actions="; ".join(info["key_actions"]),
                activities="; ".join(info["activities"]),
                threat_level=info["threat_level"],
            )

    def _handle_disconnected_device(
        self,
        info: Dict[str, Any],
        callback: Optional[Callable[[str, DeviceSnapshot, List[str], str, bool, str], None]],
    ) -> None:
        snapshot = info["snapshot"]
        duration = int(time.time() - info["connected_epoch"])
        disconnect_time = self._now_str()

        key_actions = info["key_actions"] + ["USB_REMOVED"]
        status = info["status"]
        if not status.startswith("BLOCKED"):
            status = "DISCONNECTED"

        self._update_session_log(
            info["session_id"],
            disconnection_time=disconnect_time,
            duration_seconds=duration,
            status=status,
            file_count_final=int(info["last_file_count"]),
            files_accessed=int(info["files_accessed"]),
            key_actions="; ".join(key_actions),
            activities="; ".join(info["activities"]),
            threat_level=info["threat_level"],
        )

        self._log_system_event("USB_REMOVED", snapshot, f"Disconnected after {duration} seconds")

        if callback:
            callback(
                "disconnected",
                snapshot,
                info["activities"],
                info["threat_level"],
                bool(info["unauthorized"]),
                status,
            )

    def monitor_usb_devices(
        self,
        callback: Optional[Callable[[str, DeviceSnapshot, List[str], str, bool, str], None]] = None,
    ) -> None:
        """Main monitoring loop with real-time callbacks."""
        self._monitoring = True
        self._stop_event.clear()
        known_devices = self._discover_devices()
        self._log_system_event("MONITOR_STARTED", None, "Monitoring started")

        while self._monitoring and not self._stop_event.is_set():
            try:
                current = self._discover_devices()

                connected = [k for k in current if k not in known_devices]
                disconnected = [k for k in known_devices if k not in current]

                for key in connected:
                    self._handle_connected_device(current[key], callback)

                for key, info in list(self.active_devices.items()):
                    if key not in disconnected:
                        self._refresh_active_device(info, callback)

                for key in disconnected:
                    info = self.active_devices.pop(key, None)
                    if info is not None:
                        self._handle_disconnected_device(info, callback)

                known_devices = current
                self._stop_event.wait(self.poll_interval)
            except Exception as exc:
                self._log_system_event("MONITOR_ERROR", None, str(exc))
                self._stop_event.wait(self.poll_interval)

        self._monitoring = False
        self._log_system_event("MONITOR_STOPPED", None, "Monitoring stopped")


if __name__ == "__main__":
    monitor = USBMonitor()
    monitor.monitor_usb_devices()
