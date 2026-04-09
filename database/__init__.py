#!/usr/bin/env python3
"""
KaliGuard AI - Database Initialization Module

Creates and initializes all SQLite databases used by KaliGuard AI:
- devices.db    : Discovered network devices
- vulnerabilities.db : Known vulnerabilities database
- sessions.db   : Scan sessions and security findings

Run this module directly to initialize all databases:
    python database/__init__.py
"""

import sqlite3
import os
import logging
from datetime import datetime

logger = logging.getLogger("kaliguard.database")


def init_devices_db(db_path: str = "database/devices.db") -> bool:
    """
    Initialize the devices database.

    Creates the devices table for storing discovered network devices
    with their IP, MAC, hostname, OS, open ports, and discovery timestamp.

    Args:
        db_path: Path to the devices SQLite database file

    Returns:
        True if successful, False otherwise
    """
    try:
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                operating_system TEXT,
                open_ports TEXT,
                services TEXT,
                vendor TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                session_id TEXT,
                notes TEXT,
                UNIQUE(ip_address)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                state TEXT DEFAULT 'open',
                service_name TEXT,
                service_version TEXT,
                banner TEXT,
                last_scanned TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ports_device ON device_ports(device_ip)
        """)

        conn.commit()
        conn.close()
        logger.info(f"Devices database initialized: {db_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize devices DB: {e}")
        return False


def init_vulnerabilities_db(db_path: str = "database/vulnerabilities.db") -> bool:
    """
    Initialize the vulnerabilities database.

    Creates the vulns table for storing discovered vulnerabilities with
    CVE references, CVSS scores, affected targets, and remediation info.

    Args:
        db_path: Path to the vulnerabilities SQLite database file

    Returns:
        True if successful, False otherwise
    """
    try:
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                target TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                vuln_name TEXT NOT NULL,
                cve_id TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
                description TEXT NOT NULL,
                evidence TEXT,
                remediation TEXT,
                references TEXT,
                exploit_available INTEGER DEFAULT 0,
                patch_available INTEGER DEFAULT 0,
                first_detected TEXT NOT NULL,
                last_confirmed TEXT,
                status TEXT DEFAULT 'open' CHECK(status IN ('open', 'confirmed', 'mitigated', 'resolved', 'false_positive')),
                verified_by TEXT,
                notes TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id INTEGER REFERENCES vulns(id),
                exploit_db_id TEXT,
                exploit_title TEXT,
                exploit_type TEXT,
                platform TEXT,
                path TEXT,
                verified INTEGER DEFAULT 0,
                added_date TEXT
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulns_target ON vulns(target)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulns(severity)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulns_session ON vulns(session_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulns(cve_id)
        """)

        conn.commit()
        conn.close()
        logger.info(f"Vulnerabilities database initialized: {db_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize vulnerabilities DB: {e}")
        return False


def init_sessions_db(db_path: str = "database/sessions.db") -> bool:
    """
    Initialize the sessions database.

    Creates sessions and findings tables for storing scan session data
    and discovered security findings associated with each session.

    Args:
        db_path: Path to the sessions SQLite database file

    Returns:
        True if successful, False otherwise
    """
    try:
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                target_scope TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                completed_at TEXT,
                status TEXT DEFAULT 'active' CHECK(status IN ('active', 'completed', 'archived', 'failed')),
                session_type TEXT DEFAULT 'general',
                operator TEXT,
                notes TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                category TEXT NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
                description TEXT NOT NULL,
                target TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                cve_id TEXT,
                cvss_score REAL,
                evidence TEXT,
                remediation TEXT,
                tool_used TEXT,
                false_positive INTEGER DEFAULT 0,
                verified INTEGER DEFAULT 0,
                timestamp TEXT NOT NULL,
                updated_at TEXT,
                status TEXT DEFAULT 'open' CHECK(status IN ('open', 'confirmed', 'mitigated', 'resolved', 'false_positive'))
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                tool_name TEXT NOT NULL,
                target TEXT,
                command TEXT,
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
                started_at TEXT,
                completed_at TEXT,
                exit_code INTEGER,
                output_file TEXT,
                error_log TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                role TEXT NOT NULL CHECK(role IN ('user', 'assistant', 'system')),
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                tokens_used INTEGER
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_session ON scan_jobs(session_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_history(session_id)
        """)

        conn.commit()
        conn.close()
        logger.info(f"Sessions database initialized: {db_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize sessions DB: {e}")
        return False


def init_all_databases(base_dir: str = "database") -> dict:
    """
    Initialize all KaliGuard AI databases.

    Creates the database directory and initializes all three databases
    with proper schema and indexes.

    Args:
        base_dir: Base directory for database files

    Returns:
        dict with success status for each database
    """
    os.makedirs(base_dir, exist_ok=True)

    results = {
        "devices_db": init_devices_db(os.path.join(base_dir, "devices.db")),
        "vulnerabilities_db": init_vulnerabilities_db(os.path.join(base_dir, "vulnerabilities.db")),
        "sessions_db": init_sessions_db(os.path.join(base_dir, "sessions.db")),
    }

    all_success = all(results.values())
    if all_success:
        logger.info("All KaliGuard databases initialized successfully")
    else:
        failed = [k for k, v in results.items() if not v]
        logger.error(f"Failed to initialize databases: {failed}")

    return results


def get_db_stats(base_dir: str = "database") -> dict:
    """
    Get statistics about all databases (record counts, file sizes).

    Args:
        base_dir: Base directory containing database files

    Returns:
        dict with database statistics
    """
    stats = {}
    db_files = {
        "devices.db": ["devices", "device_ports"],
        "vulnerabilities.db": ["vulns", "exploits"],
        "sessions.db": ["sessions", "findings", "scan_jobs", "chat_history"],
    }

    for db_file, tables in db_files.items():
        db_path = os.path.join(base_dir, db_file)
        if not os.path.exists(db_path):
            stats[db_file] = {"status": "not found"}
            continue

        file_size = os.path.getsize(db_path)
        db_stats = {"size_bytes": file_size, "tables": {}}

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    db_stats["tables"][table] = count
                except sqlite3.OperationalError:
                    db_stats["tables"][table] = "table not found"
            conn.close()
        except Exception as e:
            db_stats["error"] = str(e)

        stats[db_file] = db_stats

    return stats


if __name__ == "__main__":
    # Run database initialization when module is executed directly
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    print("KaliGuard AI - Database Initialization")
    print("=" * 50)

    results = init_all_databases()

    for db_name, success in results.items():
        status = "OK" if success else "FAILED"
        icon = "✓" if success else "✗"
        print(f"  [{icon}] {db_name}: {status}")

    print()
    stats = get_db_stats()
    print("Database Statistics:")
    for db_file, info in stats.items():
        print(f"  {db_file}:")
        if "tables" in info:
            for table, count in info["tables"].items():
                print(f"    - {table}: {count} records")
            print(f"    - Size: {info.get('size_bytes', 0)} bytes")

    print()
    all_ok = all(results.values())
    if all_ok:
        print("[SUCCESS] All databases initialized successfully!")
    else:
        print("[ERROR] Some databases failed to initialize. Check logs.")
        import sys
        sys.exit(1)
