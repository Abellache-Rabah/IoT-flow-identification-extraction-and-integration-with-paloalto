import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from database import get_db
from models import FlowOut, FlowUpdate, BulkFlowUpdate
from config import PROFILES_DIR
from services.flow_service import extract_flows

router = APIRouter(prefix="/api", tags=["flows"])


@router.post("/devices/{device_id}/captures/{capture_id}/extract-flows")
async def extract_device_flows(device_id: str, capture_id: str):
    """Extract and aggregate flows from Zeek logs, merge into DB (dedup by key)."""
    db = await get_db()

    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    device = await cursor.fetchone()
    if not device:
        raise HTTPException(404, "Device not found")

    output_dir = str(PROFILES_DIR / device_id / f"zeek_{capture_id}")
    device_ip = dict(device).get("ip_address", "")
    flows = extract_flows(output_dir, device_ip)

    # Load existing flows for this device to deduplicate
    cursor = await db.execute(
        "SELECT id, src_ip, dst_ip, dst_port, protocol, bytes_total, packets_total, connection_count FROM flows WHERE device_id = ?",
        (device_id,),
    )
    existing_rows = await cursor.fetchall()
    existing_map = {}
    for r in existing_rows:
        row = dict(r)
        key = (row["src_ip"], row["dst_ip"], row["dst_port"], row["protocol"])
        existing_map[key] = row

    inserted = 0
    updated = 0
    for f in flows:
        key = (f["src_ip"], f["dst_ip"], f["dst_port"], f["protocol"])
        if key in existing_map:
            # Merge: update counters on existing row
            ex = existing_map[key]
            await db.execute(
                """UPDATE flows SET bytes_total = bytes_total + ?, packets_total = packets_total + ?,
                   connection_count = connection_count + ?, capture_id = ?,
                   app_protocol = CASE WHEN app_protocol = '' THEN ? ELSE app_protocol END,
                   dns_name = CASE WHEN dns_name = '' THEN ? ELSE dns_name END,
                   sni = CASE WHEN sni = '' THEN ? ELSE sni END
                   WHERE id = ?""",
                (f["bytes_total"], f["packets_total"], f["connection_count"],
                 capture_id, f["app_protocol"], f["dns_name"], f["sni"], ex["id"]),
            )
            updated += 1
        else:
            # Insert new flow
            flow_id = str(uuid.uuid4())[:8]
            await db.execute(
                """INSERT INTO flows
                   (id, device_id, capture_id, src_ip, dst_ip, src_port, dst_port,
                    protocol, app_protocol, service_group, dns_name, sni,
                    bytes_total, packets_total, connection_count, allowed, notes)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,'')""",
                (flow_id, device_id, capture_id,
                 f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"],
                 f["protocol"], f["app_protocol"], f["service_group"],
                 f["dns_name"], f["sni"],
                 f["bytes_total"], f["packets_total"], f["connection_count"]),
            )
            existing_map[key] = {"id": flow_id}
            inserted += 1

    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "UPDATE devices SET status = 'flows_extracted', updated_at = ? WHERE id = ?",
        (now, device_id),
    )
    await db.commit()

    return {"total_flows": inserted + updated, "new_flows": inserted, "merged_flows": updated, "flows_extracted": True}


@router.get("/devices/{device_id}/flows", response_model=list[FlowOut])
async def list_flows(
    device_id: str,
    capture_id: str = None,
    service_group: str = None,
    allowed_only: bool = False,
):
    """List flows for a device with optional filters."""
    db = await get_db()

    query = "SELECT * FROM flows WHERE device_id = ?"
    params: list = [device_id]

    if capture_id:
        query += " AND capture_id = ?"
        params.append(capture_id)
    if service_group:
        query += " AND service_group = ?"
        params.append(service_group)
    if allowed_only:
        query += " AND allowed = 1"

    query += " ORDER BY bytes_total DESC"

    cursor = await db.execute(query, params)
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


@router.patch("/devices/{device_id}/flows/{flow_id}", response_model=FlowOut)
async def update_flow(device_id: str, flow_id: str, data: FlowUpdate):
    """Update a flow's allowed status or notes."""
    db = await get_db()

    updates = data.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(400, "No updates provided")

    set_parts = []
    values = []
    for k, v in updates.items():
        set_parts.append(f"{k} = ?")
        values.append(v if not isinstance(v, bool) else int(v))

    values.extend([flow_id, device_id])
    await db.execute(
        f"UPDATE flows SET {', '.join(set_parts)} WHERE id = ? AND device_id = ?",
        values,
    )
    await db.commit()

    cursor = await db.execute("SELECT * FROM flows WHERE id = ?", (flow_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(404, "Flow not found")
    return dict(row)


@router.post("/devices/{device_id}/flows/bulk-update")
async def bulk_update_flows(device_id: str, data: BulkFlowUpdate):
    """Bulk update allowed status for multiple flows."""
    db = await get_db()
    placeholders = ",".join("?" for _ in data.flow_ids)
    await db.execute(
        f"UPDATE flows SET allowed = ? WHERE id IN ({placeholders}) AND device_id = ?",
        [int(data.allowed)] + data.flow_ids + [device_id],
    )

    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "UPDATE devices SET status = 'reviewed', updated_at = ? WHERE id = ?",
        (now, device_id),
    )
    await db.commit()
    return {"updated": len(data.flow_ids)}


@router.delete("/devices/{device_id}/flows")
async def clear_all_flows(device_id: str):
    """Delete ALL flows for a device (reset)."""
    db = await get_db()
    cursor = await db.execute("SELECT COUNT(*) as count FROM flows WHERE device_id = ?", (device_id,))
    row = await cursor.fetchone()
    count = dict(row)["count"]
    await db.execute("DELETE FROM flows WHERE device_id = ?", (device_id,))
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "UPDATE devices SET status = 'analyzed', updated_at = ? WHERE id = ?",
        (now, device_id),
    )
    await db.commit()
    return {"deleted": count}


@router.get("/devices/{device_id}/flows/service-groups")
async def get_service_groups(device_id: str):
    """Get unique service groups and counts for a device's flows."""
    db = await get_db()
    cursor = await db.execute(
        """SELECT service_group, COUNT(*) as count, SUM(allowed) as allowed_count
           FROM flows WHERE device_id = ? GROUP BY service_group ORDER BY count DESC""",
        (device_id,),
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]
