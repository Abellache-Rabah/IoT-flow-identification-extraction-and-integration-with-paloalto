"""
URL extraction from Zeek analysis results.
Reads DNS query names and TLS/SSL SNI hostnames from Zeek logs (already parsed
by zeek_service) for all analyzed captures of a device.
"""

from fastapi import APIRouter, HTTPException
from database import get_db
from config import PROFILES_DIR
from services.zeek_service import get_dns_queries, get_ssl_connections

router = APIRouter(prefix="/api", tags=["urls"])


@router.get("/devices/{device_id}/urls")
async def extract_urls(device_id: str):
    """
    Extract all hostnames from Zeek analysis output for all captures of a device.
    Collects:
      - DNS query names (from dns.log)
      - TLS/SSL server names / SNI (from ssl.log)
    Returns a deduplicated sorted list.
    """
    db = await get_db()
    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    if not await cursor.fetchone():
        raise HTTPException(404, "Device not found")

    cursor = await db.execute(
        "SELECT id FROM captures WHERE device_id = ? ORDER BY started_at",
        (device_id,),
    )
    rows = await cursor.fetchall()

    all_urls: set[str] = set()
    analyzed_count = 0

    for row in rows:
        capture_id = row["id"]
        output_dir = str(PROFILES_DIR / device_id / f"zeek_{capture_id}")

        # DNS query names
        try:
            dns_records = get_dns_queries(output_dir)
            for r in dns_records:
                q = r.get("query", "").strip().strip(".")
                # Skip raw IPs and empty / PTR names
                if q and not q.replace(".", "").isdigit() and not q.endswith(".arpa"):
                    all_urls.add(q)
            if dns_records:
                analyzed_count += 1
        except Exception:
            pass

        # TLS SNI / server names
        try:
            ssl_records = get_ssl_connections(output_dir)
            for r in ssl_records:
                sni = r.get("server_name", "").strip().strip(".")
                if sni and sni != "-":
                    all_urls.add(sni)
        except Exception:
            pass

    return {
        "urls": sorted(all_urls),
        "analyzed_count": analyzed_count,
        "capture_count": len(rows),
    }


@router.get("/devices/{device_id}/captures/{capture_id}/urls")
async def extract_urls_for_capture(device_id: str, capture_id: str):
    """
    Extract hostnames from Zeek analysis of a single capture.
    """
    output_dir = str(PROFILES_DIR / device_id / f"zeek_{capture_id}")

    urls: set[str] = set()

    try:
        for r in get_dns_queries(output_dir):
            q = r.get("query", "").strip().strip(".")
            if q and not q.replace(".", "").isdigit() and not q.endswith(".arpa"):
                urls.add(q)
    except Exception:
        pass

    try:
        for r in get_ssl_connections(output_dir):
            sni = r.get("server_name", "").strip().strip(".")
            if sni and sni != "-":
                urls.add(sni)
    except Exception:
        pass

    return {"urls": sorted(urls)}
