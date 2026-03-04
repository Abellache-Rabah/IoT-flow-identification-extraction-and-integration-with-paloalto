import uuid
import json
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from database import get_db
from models import RuleExportConfig, RuleExportOut
from services.rule_service import generate_rules

router = APIRouter(prefix="/api", tags=["rules"])


@router.post("/devices/{device_id}/generate-rules")
async def generate_device_rules(device_id: str, config: RuleExportConfig):
    """Generate Palo Alto rules from allowed flows."""
    db = await get_db()

    # Get device info
    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    device = await cursor.fetchone()
    if not device:
        raise HTTPException(404, "Device not found")

    # Get allowed flows
    cursor = await db.execute(
        "SELECT * FROM flows WHERE device_id = ? AND allowed = 1 ORDER BY service_group",
        (device_id,),
    )
    rows = await cursor.fetchall()
    flows = [dict(r) for r in rows]

    if not flows:
        raise HTTPException(400, "No allowed flows. Review and allow flows first.")

    # Add device name to variables if not set
    variables = config.variables.copy()
    if "device_name" not in variables:
        variables["device_name"] = dict(device)["name"].replace(" ", "-").lower()

    rules_text = generate_rules(flows, variables, config.format)

    # Save export record
    export_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        """INSERT INTO rule_exports (id, device_id, format, variables_json, rules_text, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (export_id, device_id, config.format, json.dumps(variables), rules_text, now),
    )
    await db.execute(
        "UPDATE devices SET status = 'rules_generated', updated_at = ? WHERE id = ?",
        (now, device_id),
    )
    await db.commit()

    return {
        "id": export_id,
        "format": config.format,
        "rules_text": rules_text,
        "flow_count": len(flows),
    }


@router.get("/devices/{device_id}/exports", response_model=list[RuleExportOut])
async def list_exports(device_id: str):
    """List previous rule exports for a device."""
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM rule_exports WHERE device_id = ? ORDER BY created_at DESC",
        (device_id,),
    )
    return [dict(r) for r in await cursor.fetchall()]


@router.get("/devices/{device_id}/exports/{export_id}", response_model=RuleExportOut)
async def get_export(device_id: str, export_id: str):
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM rule_exports WHERE id = ? AND device_id = ?",
        (export_id, device_id),
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(404, "Export not found")
    return dict(row)
