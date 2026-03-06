import asyncio
import os
import shlex
import signal
from datetime import datetime, timezone
from pathlib import Path
from collections import deque
from config import TCPDUMP_BIN, CAPTURE_INTERFACE

# Active captures: device_id -> capture state dict
_active_captures: dict[str, dict] = {}


def _count_pcap_packets(pcap_path: str) -> int | None:
    """Count packets in a PCAP file by parsing the binary structure.
    PCAP global header = 24 bytes; each record header = 16 bytes (ts_sec, ts_usec, incl_len, orig_len).
    Returns packet count, or None if file is unreadable/incomplete.
    """
    import struct
    GLOBAL_HEADER = 24
    REC_HEADER = 16
    try:
        with open(pcap_path, "rb") as f:
            header = f.read(GLOBAL_HEADER)
            if len(header) < GLOBAL_HEADER:
                return None
            magic = struct.unpack_from("<I", header)[0]
            if magic == 0xa1b2c3d4:
                byte_order = "<"
            elif magic == 0xd4c3b2a1:
                byte_order = ">"
            else:
                return None  # not a pcap file
            count = 0
            while True:
                rec = f.read(REC_HEADER)
                if len(rec) < REC_HEADER:
                    break
                incl_len = struct.unpack_from(f"{byte_order}I", rec, 8)[0]
                f.seek(incl_len, 1)  # skip packet data
                count += 1
        return count
    except Exception:
        return None


def _get_capture_state(device_id: str) -> dict | None:
    return _active_captures.get(device_id)


async def start_capture_background(
    device_id: str,
    capture_id: str,
    pcap_path: str,
    interface: str,
    bpf_filter: str,
    duration_seconds: int,
):
    """Start tcpdump capture as an async background task."""
    iface = interface or CAPTURE_INTERFACE
    Path(pcap_path).parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        TCPDUMP_BIN,
        "-i", iface,
        "-w", pcap_path,
        "-U",  # packet-buffered output
        "-l",  # line-buffered stdout
    ]

    if bpf_filter:
        cmd.extend(shlex.split(bpf_filter))

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    state = {
        "process": process,
        "capture_id": capture_id,
        "pcap_path": pcap_path,
        "packet_count": 0,
        "file_size": 0,
        "started_at": datetime.now(timezone.utc),
        "completed_at": None,
        "running": True,
        "logs": deque(maxlen=200),  # keep last 200 lines
        "error": None,
    }
    _active_captures[device_id] = state

    # Background task to read output
    async def _read_loop():
        try:
            while True:
                line = await process.stderr.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if text:
                    state["logs"].append(text)
                    if "packets captured" in text or "packets received" in text:
                        try:
                            state["packet_count"] = int(text.split()[0])
                        except (ValueError, IndexError):
                            pass
        except asyncio.CancelledError:
            pass

    # Background task for auto-stop
    async def _auto_stop():
        if duration_seconds > 0:
            await asyncio.sleep(duration_seconds)
            await stop_capture(device_id)

    asyncio.create_task(_read_loop())
    if duration_seconds > 0:
        asyncio.create_task(_auto_stop())

    # Periodically update file size + packet count from the PCAP binary
    async def _update_stats():
        while state["running"]:
            await asyncio.sleep(2)
            if os.path.exists(pcap_path):
                try:
                    state["file_size"] = os.path.getsize(pcap_path)
                    count = _count_pcap_packets(pcap_path)
                    if count is not None:
                        state["packet_count"] = count
                except Exception:
                    pass

    asyncio.create_task(_update_stats())

    # Wait for process to finish in background
    async def _wait():
        await process.wait()
        state["running"] = False
        state["completed_at"] = datetime.now(timezone.utc).isoformat()
        if os.path.exists(pcap_path):
            state["file_size"] = os.path.getsize(pcap_path)
            count = _count_pcap_packets(pcap_path)
            if count is not None:
                state["packet_count"] = count

    asyncio.create_task(_wait())


async def stop_capture(device_id: str) -> bool:
    """Stop an active capture for a device."""
    state = _active_captures.get(device_id)
    if not state:
        return False
    process = state.get("process")
    if process and process.returncode is None:
        try:
            process.send_signal(signal.SIGINT)
            await asyncio.wait_for(process.wait(), timeout=5)
        except (asyncio.TimeoutError, ProcessLookupError):
            process.kill()
        state["running"] = False
        state["completed_at"] = datetime.now(timezone.utc).isoformat()
        pcap_path = state.get("pcap_path", "")
        if os.path.exists(pcap_path):
            state["file_size"] = os.path.getsize(pcap_path)
        return True
    return False


def is_capturing(device_id: str) -> bool:
    """Check if a capture is active for a device."""
    state = _active_captures.get(device_id)
    return state is not None and state.get("running", False)


def get_capture_status(device_id: str) -> dict:
    """Get current capture status including logs."""
    state = _active_captures.get(device_id)
    if not state:
        return {"running": False, "logs": [], "packet_count": 0, "file_size": 0, "elapsed_seconds": 0}

    elapsed = 0
    if state.get("started_at"):
        elapsed = int((datetime.now(timezone.utc) - state["started_at"]).total_seconds())

    return {
        "running": state.get("running", False),
        "capture_id": state.get("capture_id", ""),
        "packet_count": state.get("packet_count", 0),
        "file_size": state.get("file_size", 0),
        "elapsed_seconds": elapsed,
        "completed_at": state.get("completed_at"),
        "logs": list(state.get("logs", [])),
    }
