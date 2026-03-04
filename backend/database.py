import aiosqlite
from config import DB_PATH

_db: aiosqlite.Connection | None = None


async def get_db() -> aiosqlite.Connection:
    global _db
    if _db is None:
        _db = await aiosqlite.connect(str(DB_PATH))
        _db.row_factory = aiosqlite.Row
        await _db.execute("PRAGMA journal_mode=WAL")
        await _db.execute("PRAGMA foreign_keys=ON")
        await init_tables(_db)
    return _db


async def close_db():
    global _db
    if _db:
        await _db.close()
        _db = None


async def init_tables(db: aiosqlite.Connection):
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            device_type TEXT DEFAULT '',
            vendor TEXT DEFAULT '',
            mac_address TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            description TEXT DEFAULT '',
            status TEXT DEFAULT 'new',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS captures (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            pcap_path TEXT NOT NULL,
            interface TEXT NOT NULL,
            bpf_filter TEXT DEFAULT '',
            duration_seconds INTEGER DEFAULT 0,
            packet_count INTEGER DEFAULT 0,
            file_size INTEGER DEFAULT 0,
            started_at TEXT NOT NULL,
            completed_at TEXT DEFAULT '',
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS flows (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            capture_id TEXT NOT NULL,
            src_ip TEXT DEFAULT '',
            dst_ip TEXT DEFAULT '',
            src_port INTEGER DEFAULT 0,
            dst_port INTEGER DEFAULT 0,
            protocol TEXT DEFAULT '',
            app_protocol TEXT DEFAULT '',
            service_group TEXT DEFAULT '',
            dns_name TEXT DEFAULT '',
            sni TEXT DEFAULT '',
            bytes_total INTEGER DEFAULT 0,
            packets_total INTEGER DEFAULT 0,
            connection_count INTEGER DEFAULT 1,
            allowed INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
            FOREIGN KEY (capture_id) REFERENCES captures(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS rule_exports (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            format TEXT NOT NULL,
            variables_json TEXT DEFAULT '{}',
            rules_text TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );
    """)
    await db.commit()
