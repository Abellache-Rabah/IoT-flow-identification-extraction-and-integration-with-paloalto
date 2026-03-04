import uuid
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
import shutil
from fastapi import APIRouter, HTTPException, UploadFile, File
from database import get_db
from models import CaptureConfig, CaptureOut
from services.capture_service import (
    start_capture_background, stop_capture, is_capturing, get_capture_status,
)
from config import PROFILES_DIR, CAPTURE_INTERFACE

router = APIRouter(prefix="/api", tags=["capture"])


@router.post("/devices/{device_id}/captures", response_model=CaptureOut, status_code=201)
async def create_capture(device_id: str, config: CaptureConfig):
    """Create a capture record (does NOT start capture yet — call /start)."""
    db = await get_db()
    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    device = await cursor.fetchone()
    if not device:
        raise HTTPException(404, "Device not found")

    if is_capturing(device_id):
        raise HTTPException(409, "Capture already in progress for this device")

    capture_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    iface = config.interface or CAPTURE_INTERFACE

    profile_dir = PROFILES_DIR / device_id
    profile_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = str(profile_dir / f"capture_{capture_id}.pcap")

    bpf_filter = config.bpf_filter
    if not bpf_filter and dict(device).get("mac_address"):
        bpf_filter = f"ether host {dict(device)['mac_address']}"

    await db.execute(
        """INSERT INTO captures (id, device_id, pcap_path, interface, bpf_filter, duration_seconds, packet_count, file_size, started_at, completed_at)
           VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, '')""",
        (capture_id, device_id, pcap_path, iface, bpf_filter,
         config.duration_seconds, now),
    )
    await db.execute(
        "UPDATE devices SET status = 'capturing', updated_at = ? WHERE id = ?",
        (now, device_id),
    )
    await db.commit()

    # Start capture immediately in background
    await start_capture_background(
        device_id=device_id,
        capture_id=capture_id,
        pcap_path=pcap_path,
        interface=iface,
        bpf_filter=bpf_filter,
        duration_seconds=config.duration_seconds,
    )

    cursor = await db.execute("SELECT * FROM captures WHERE id = ?", (capture_id,))
    return dict(await cursor.fetchone())


@router.get("/devices/{device_id}/captures", response_model=list[CaptureOut])
async def list_captures(device_id: str):
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM captures WHERE device_id = ? ORDER BY started_at DESC",
        (device_id,),
    )
    return [dict(r) for r in await cursor.fetchall()]


@router.post("/devices/{device_id}/upload-pcap", status_code=201)
async def upload_pcap(device_id: str, file: UploadFile = File(...)):
    """Upload an existing PCAP file for analysis."""
    db = await get_db()
    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    device = await cursor.fetchone()
    if not device:
        raise HTTPException(404, "Device not found")

    # Validate file type
    fname = file.filename or "upload.pcap"
    if not fname.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(400, "File must be a .pcap, .pcapng, or .cap file")

    capture_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()

    profile_dir = PROFILES_DIR / device_id
    profile_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = str(profile_dir / f"capture_{capture_id}.pcap")

    # Save uploaded file
    with open(pcap_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    import os
    file_size = os.path.getsize(pcap_path)

    await db.execute(
        """INSERT INTO captures (id, device_id, pcap_path, interface, bpf_filter, duration_seconds, packet_count, file_size, started_at, completed_at)
           VALUES (?, ?, ?, 'upload', '', 0, 0, ?, ?, ?)""",
        (capture_id, device_id, pcap_path, file_size, now, now),
    )
    await db.execute(
        "UPDATE devices SET status = 'captured', updated_at = ? WHERE id = ?",
        (now, device_id),
    )
    await db.commit()

    cursor = await db.execute("SELECT * FROM captures WHERE id = ?", (capture_id,))
    return dict(await cursor.fetchone())


@router.post("/devices/{device_id}/captures/{capture_id}/stop")
async def stop_device_capture(device_id: str, capture_id: str):
    """Manually stop an active capture."""
    stopped = await stop_capture(device_id)
    if not stopped:
        raise HTTPException(404, "No active capture for this device")

    # Update DB
    status = get_capture_status(device_id)
    db = await get_db()
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        """UPDATE captures SET packet_count = ?, file_size = ?, completed_at = ?
           WHERE id = ?""",
        (status["packet_count"], status["file_size"], now, capture_id),
    )
    await db.execute(
        "UPDATE devices SET status = 'captured', updated_at = ? WHERE id = ?",
        (now, device_id),
    )
    await db.commit()

    return {"status": "stopped", "packet_count": status["packet_count"], "file_size": status["file_size"]}


@router.get("/devices/{device_id}/capture-status")
async def get_device_capture_status(device_id: str):
    """Poll capture status — returns running state, packet count, logs, elapsed time."""
    status = get_capture_status(device_id)

    # If capture just finished, update DB
    if not status["running"] and status.get("capture_id") and status.get("completed_at"):
        db = await get_db()
        cap_id = status["capture_id"]
        await db.execute(
            """UPDATE captures SET packet_count = ?, file_size = ?, completed_at = ?
               WHERE id = ? AND completed_at = ''""",
            (status["packet_count"], status["file_size"], status["completed_at"], cap_id),
        )
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            "UPDATE devices SET status = 'captured', updated_at = ? WHERE id = ? AND status = 'capturing'",
            (now, device_id),
        )
        await db.commit()

    return status
