import os
from pathlib import Path

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "iot_onboarding.db"
PROFILES_DIR = DATA_DIR / "profiles"

CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")
TCPDUMP_BIN = os.getenv("TCPDUMP_BIN", "/usr/bin/tcpdump")
ZEEK_BIN = os.getenv("ZEEK_BIN", "/usr/local/zeek/bin/zeek")

APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("APP_PORT", "8080"))

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
PROFILES_DIR.mkdir(parents=True, exist_ok=True)
