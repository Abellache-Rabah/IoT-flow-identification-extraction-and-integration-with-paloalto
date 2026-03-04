import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from database import get_db
from models import DeviceCreate, DeviceUpdate, DeviceOut

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("", response_model=list[DeviceOut])
async def list_devices():
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM devices ORDER BY updated_at DESC"
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


@router.post("", response_model=DeviceOut, status_code=201)
async def create_device(data: DeviceCreate):
    db = await get_db()
    now = datetime.now(timezone.utc).isoformat()
    device_id = str(uuid.uuid4())[:8]

    await db.execute(
        """INSERT INTO devices (id, name, device_type, vendor, mac_address, ip_address, description, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)""",
        (device_id, data.name, data.device_type, data.vendor,
         data.mac_address, data.ip_address, data.description, now, now),
    )
    await db.commit()

    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    row = await cursor.fetchone()
    return dict(row)


@router.get("/{device_id}", response_model=DeviceOut)
async def get_device(device_id: str):
    db = await get_db()
    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(404, "Device not found")
    return dict(row)


@router.patch("/{device_id}", response_model=DeviceOut)
async def update_device(device_id: str, data: DeviceUpdate):
    db = await get_db()
    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(404, "Device not found")

    updates = data.model_dump(exclude_unset=True)
    if not updates:
        return dict(row)

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [device_id]

    await db.execute(f"UPDATE devices SET {set_clause} WHERE id = ?", values)
    await db.commit()

    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    return dict(await cursor.fetchone())


@router.delete("/{device_id}", status_code=204)
async def delete_device(device_id: str):
    db = await get_db()
    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    if not await cursor.fetchone():
        raise HTTPException(404, "Device not found")

    await db.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    await db.commit()


@router.get("/{device_id}/summary")
async def get_device_summary(device_id: str):
    """Get a full summary of a device: captures, flows, exports."""
    db = await get_db()
    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    device = await cursor.fetchone()
    if not device:
        raise HTTPException(404, "Device not found")

    cursor = await db.execute(
        "SELECT * FROM captures WHERE device_id = ? ORDER BY started_at DESC",
        (device_id,),
    )
    captures = [dict(r) for r in await cursor.fetchall()]

    cursor = await db.execute(
        "SELECT COUNT(*) as total, SUM(allowed) as allowed FROM flows WHERE device_id = ?",
        (device_id,),
    )
    flow_stats = dict(await cursor.fetchone())

    cursor = await db.execute(
        "SELECT * FROM rule_exports WHERE device_id = ? ORDER BY created_at DESC LIMIT 5",
        (device_id,),
    )
    exports = [dict(r) for r in await cursor.fetchall()]

    return {
        "device": dict(device),
        "captures": captures,
        "flow_stats": flow_stats,
        "recent_exports": exports,
    }
