from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query
from database import get_db
from config import PROFILES_DIR
from services.zeek_service import (
    run_zeek_analysis, get_connections, get_dns_queries,
    get_ssl_connections, get_http_requests, get_ot_logs,
    get_protocol_summary,
)
from services.flow_service import extract_flows
from services.flow_persist import merge_flows_into_db

router = APIRouter(prefix="/api", tags=["analysis"])


@router.post("/devices/{device_id}/captures/{capture_id}/analyze")
async def analyze_capture(device_id: str, capture_id: str):
    """Run Zeek analysis on a captured pcap file and auto-extract flows."""
    db = await get_db()
    cursor = await db.execute("SELECT * FROM captures WHERE id = ?", (capture_id,))
    capture = await cursor.fetchone()
    if not capture:
        raise HTTPException(404, "Capture not found")

    cap = dict(capture)
    output_dir = str(PROFILES_DIR / device_id / f"zeek_{capture_id}")

    result = await run_zeek_analysis(cap["pcap_path"], output_dir)

    if not result.get("success"):
        raise HTTPException(500, f"Zeek analysis failed: {result.get('error', 'Unknown error')}")

    # Auto-extract flows from Zeek logs and merge into DB
    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    device = await cursor.fetchone()
    device_ip = dict(device).get("ip_address", "") if device else ""
    flows = extract_flows(output_dir, device_ip)
    flow_stats = await merge_flows_into_db(db=db, device_id=device_id, capture_id=capture_id, flows=flows)

    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "UPDATE devices SET status = 'analyzed', updated_at = ? WHERE id = ?",
        (now, device_id),
    )
    await db.commit()

    return {**result, "flow_extraction": flow_stats}


@router.get("/devices/{device_id}/captures/{capture_id}/summary")
async def get_analysis_summary(device_id: str, capture_id: str):
    """Get protocol summary of an analyzed capture."""
    output_dir = str(PROFILES_DIR / device_id / f"zeek_{capture_id}")
    summary = get_protocol_summary(output_dir)
    return summary


@router.get("/devices/{device_id}/captures/{capture_id}/connections")
async def get_capture_connections(
    device_id: str,
    capture_id: str,
    protocol: str = Query(None),
    src_ip: str = Query(None),
    dst_ip: str = Query(None),
    dst_port: int = Query(None),
    service: str = Query(None),
    src_mac: str = Query(None),
    limit: int = Query(500),
    offset: int = Query(0),
):
    """Get connection records with filters."""
    output_dir = str(PROFILES_DIR / device_id / f"zeek_{capture_id}")
    filters = {}
    if protocol:
        filters["protocol"] = protocol
    if src_ip:
        filters["src_ip"] = src_ip
    if dst_ip:
        filters["dst_ip"] = dst_ip
    if dst_port:
        filters["dst_port"] = dst_port
    if service:
        filters["service"] = service
    if src_mac:
        filters["src_mac"] = src_mac

    records = get_connections(output_dir, filters)
    total = len(records)
    return {
        "total": total,
        "records": records[offset:offset + limit],
    }


@router.get("/devices/{device_id}/captures/{capture_id}/dns")
async def get_capture_dns(device_id: str, capture_id: str):
    output_dir = str(PROFILES_DIR / device_id / f"zeek_{capture_id}")
    return get_dns_queries(output_dir)


@router.get("/devices/{device_id}/captures/{capture_id}/ssl")
async def get_capture_ssl(device_id: str, capture_id: str):
    output_dir = str(PROFILES_DIR / device_id / f"zeek_{capture_id}")
    return get_ssl_connections(output_dir)


@router.get("/devices/{device_id}/captures/{capture_id}/http")
async def get_capture_http(device_id: str, capture_id: str):
    output_dir = str(PROFILES_DIR / device_id / f"zeek_{capture_id}")
    return get_http_requests(output_dir)


@router.get("/devices/{device_id}/captures/{capture_id}/ot")
async def get_capture_ot(device_id: str, capture_id: str):
    output_dir = str(PROFILES_DIR / device_id / f"zeek_{capture_id}")
    return get_ot_logs(output_dir)
