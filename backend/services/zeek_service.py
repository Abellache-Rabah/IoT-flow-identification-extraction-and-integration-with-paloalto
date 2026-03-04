import asyncio
import csv
import io
from pathlib import Path
from config import ZEEK_BIN


async def run_zeek_analysis(pcap_path: str, output_dir: str) -> dict:
    """Run Zeek against a pcap file and return parsed log summaries."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Run zeek with ICSNPP scripts loaded
    cmd = [
        ZEEK_BIN,
        "-r", pcap_path,
        "-C",  # ignore checksums
        f"LogAscii::use_json=T",
    ]

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(out),
    )
    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        err_text = stderr.decode("utf-8", errors="replace")
        return {"success": False, "error": err_text}

    # List generated log files
    log_files = sorted([f.name for f in out.glob("*.log")])
    return {
        "success": True,
        "log_files": log_files,
        "output_dir": str(out),
    }


def parse_zeek_log(log_path: str) -> list[dict]:
    """Parse a Zeek log file (TSV or JSON) into a list of dicts."""
    import json
    p = Path(log_path)
    if not p.exists():
        return []

    records = []
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        first_line = f.readline()
        f.seek(0)

        # Try JSON format first
        if first_line.strip().startswith("{"):
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        else:
            # TSV format with #fields header
            headers = []
            for line in f:
                line = line.strip()
                if line.startswith("#fields"):
                    headers = line.split("\t")[1:]
                elif line.startswith("#"):
                    continue
                elif headers and line:
                    values = line.split("\t")
                    record = {}
                    for i, h in enumerate(headers):
                        record[h] = values[i] if i < len(values) else ""
                    records.append(record)
    return records


def get_connections(output_dir: str, filters: dict = None) -> list[dict]:
    """Get connection records from conn.log with optional filters."""
    conn_log = Path(output_dir) / "conn.log"
    records = parse_zeek_log(str(conn_log))

    if not filters:
        return records

    filtered = []
    for r in records:
        match = True
        if filters.get("protocol") and r.get("proto", "") != filters["protocol"]:
            match = False
        if filters.get("src_ip") and r.get("id.orig_h", "") != filters["src_ip"]:
            match = False
        if filters.get("dst_ip") and r.get("id.resp_h", "") != filters["dst_ip"]:
            match = False
        if filters.get("dst_port"):
            try:
                if int(r.get("id.resp_p", 0)) != int(filters["dst_port"]):
                    match = False
            except ValueError:
                match = False
        if filters.get("service") and r.get("service", "-") != filters["service"]:
            match = False
        if filters.get("src_mac"):
            mac_filter = filters["src_mac"].lower()
            orig_mac = r.get("orig_l2_addr", "").lower()
            resp_mac = r.get("resp_l2_addr", "").lower()
            if mac_filter not in (orig_mac, resp_mac) and mac_filter not in orig_mac:
                match = False
        if match:
            filtered.append(r)
    return filtered


def get_dns_queries(output_dir: str) -> list[dict]:
    """Get DNS query records from dns.log."""
    return parse_zeek_log(str(Path(output_dir) / "dns.log"))


def get_ssl_connections(output_dir: str) -> list[dict]:
    """Get SSL/TLS connections from ssl.log."""
    return parse_zeek_log(str(Path(output_dir) / "ssl.log"))


def get_http_requests(output_dir: str) -> list[dict]:
    """Get HTTP requests from http.log."""
    return parse_zeek_log(str(Path(output_dir) / "http.log"))


def get_ot_logs(output_dir: str) -> dict[str, list[dict]]:
    """Get OT protocol logs (Modbus, DNP3, BACnet, S7comm, etc.)."""
    ot_protocols = [
        "modbus", "dnp3", "bacnet", "s7comm",
        "enip", "cip", "ethercat",
    ]
    results = {}
    out = Path(output_dir)
    for proto in ot_protocols:
        log_path = out / f"{proto}.log"
        if log_path.exists():
            results[proto] = parse_zeek_log(str(log_path))
    return results


def get_protocol_summary(output_dir: str) -> dict:
    """Get a summary of protocols detected in the capture."""
    records = get_connections(output_dir)
    protocol_counts = {}
    service_counts = {}
    total_bytes = 0

    for r in records:
        proto = r.get("proto", "unknown")
        service = r.get("service", "-")
        if service == "-":
            service = "unknown"

        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        service_counts[service] = service_counts.get(service, 0) + 1

        try:
            orig_bytes = int(r.get("orig_bytes", 0) or 0)
            resp_bytes = int(r.get("resp_bytes", 0) or 0)
            total_bytes += orig_bytes + resp_bytes
        except ValueError:
            pass

    # Add OT protocols
    ot_logs = get_ot_logs(output_dir)
    for proto, data in ot_logs.items():
        if data:
            service_counts[proto] = len(data)

    return {
        "total_connections": len(records),
        "total_bytes": total_bytes,
        "protocols": protocol_counts,
        "services": service_counts,
        "ot_protocols": list(ot_logs.keys()),
    }
