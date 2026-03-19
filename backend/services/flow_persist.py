from __future__ import annotations

from datetime import datetime, timezone


async def merge_flows_into_db(
    *,
    db,
    device_id: str,
    capture_id: str,
    flows: list[dict],
) -> dict:
    """
    Merge extracted flows into the DB.

    Dedup key: (src_ip, dst_ip, dst_port, protocol)
    - If key exists: increment counters + fill missing app/dns/sni
    - Else: insert new row (allowed defaults to 0)
    """
    import uuid

    cursor = await db.execute(
        "SELECT id, src_ip, dst_ip, dst_port, protocol FROM flows WHERE device_id = ?",
        (device_id,),
    )
    existing_rows = await cursor.fetchall()
    existing_map: dict[tuple, dict] = {}
    for r in existing_rows:
        row = dict(r)
        key = (row["src_ip"], row["dst_ip"], row["dst_port"], row["protocol"])
        existing_map[key] = row

    inserted = 0
    updated = 0

    for f in flows:
        key = (f["src_ip"], f["dst_ip"], f["dst_port"], f["protocol"])
        if key in existing_map:
            ex = existing_map[key]
            await db.execute(
                """UPDATE flows SET bytes_total = bytes_total + ?, packets_total = packets_total + ?,
                   connection_count = connection_count + ?, capture_id = ?,
                   app_protocol = CASE WHEN app_protocol = '' THEN ? ELSE app_protocol END,
                   dns_name = CASE WHEN dns_name = '' THEN ? ELSE dns_name END,
                   sni = CASE WHEN sni = '' THEN ? ELSE sni END
                   WHERE id = ?""",
                (
                    f.get("bytes_total", 0),
                    f.get("packets_total", 0),
                    f.get("connection_count", 0),
                    capture_id,
                    f.get("app_protocol", "") or "",
                    f.get("dns_name", "") or "",
                    f.get("sni", "") or "",
                    ex["id"],
                ),
            )
            updated += 1
        else:
            flow_id = str(uuid.uuid4())[:8]
            await db.execute(
                """INSERT INTO flows
                   (id, device_id, capture_id, src_ip, dst_ip, src_port, dst_port,
                    protocol, app_protocol, service_group, dns_name, sni,
                    bytes_total, packets_total, connection_count, allowed, notes)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,'')""",
                (
                    flow_id,
                    device_id,
                    capture_id,
                    f.get("src_ip", "") or "",
                    f.get("dst_ip", "") or "",
                    int(f.get("src_port", 0) or 0),
                    int(f.get("dst_port", 0) or 0),
                    f.get("protocol", "") or "",
                    f.get("app_protocol", "") or "",
                    f.get("service_group", "") or "",
                    f.get("dns_name", "") or "",
                    f.get("sni", "") or "",
                    int(f.get("bytes_total", 0) or 0),
                    int(f.get("packets_total", 0) or 0),
                    int(f.get("connection_count", 1) or 1),
                ),
            )
            existing_map[key] = {"id": flow_id}
            inserted += 1

    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "UPDATE devices SET status = 'flows_extracted', updated_at = ? WHERE id = ?",
        (now, device_id),
    )

    return {
        "total_flows": inserted + updated,
        "new_flows": inserted,
        "merged_flows": updated,
    }

