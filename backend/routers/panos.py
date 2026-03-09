import httpx
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from database import get_db

router = APIRouter(prefix="/api", tags=["panos"])


# ---- Models ----

class PanosProxyRequest(BaseModel):
    """Generic proxy to forward any request to a PAN-OS device."""
    http_method: str  # GET or POST
    url: str
    params: dict = {}
    headers: dict = {}
    json_body: Optional[dict] = None


class RulesFromFlowsRequest(BaseModel):
    variables: dict = {}


# ---- Generic Proxy ----

@router.post("/panos/proxy")
async def panos_proxy(data: PanosProxyRequest):
    """Forward an arbitrary HTTP request to a PAN-OS firewall/Panorama.
    Avoids CORS issues and allows the browser to talk to any PAN-OS device."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            if data.http_method.upper() == "POST":
                resp = await client.post(
                    data.url,
                    params=data.params or None,
                    headers=data.headers or None,
                    json=data.json_body,
                )
            else:
                resp = await client.get(
                    data.url,
                    params=data.params or None,
                    headers=data.headers or None,
                )

        return {
            "success": 200 <= resp.status_code < 300,
            "status_code": resp.status_code,
            "body": resp.text,
        }

    except httpx.ConnectError as e:
        return {"success": False, "status_code": 0, "body": f"Connection failed: {e}"}
    except httpx.TimeoutException:
        return {"success": False, "status_code": 0, "body": "Request timed out (30s)"}
    except Exception as e:
        return {"success": False, "status_code": 0, "body": f"Error: {e}"}


# ---- Build ONE rule from all allowed flows ----

@router.post("/devices/{device_id}/panos/rules-from-flows")
async def rules_from_flows(device_id: str, data: RulesFromFlowsRequest):
    """Merge ALL allowed flows into a SINGLE PAN-OS security rule.
    Collects unique destination IPs, services, etc. Deny flows are ignored."""
    db = await get_db()

    cursor = await db.execute(
        "SELECT * FROM flows WHERE device_id = ? AND allowed = 1 ORDER BY service_group",
        (device_id,),
    )
    rows = await cursor.fetchall()
    flows = [dict(r) for r in rows]

    if not flows:
        raise HTTPException(400, "No allowed flows. Review and allow flows in the Allow List first.")

    cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    device = await cursor.fetchone()
    if not device:
        raise HTTPException(404, "Device not found")

    device_dict = dict(device)
    device_name = device_dict["name"].replace(" ", "-").lower()

    # Collect unique values from all allowed flows
    dst_ips = set()
    services = set()
    src_ips = set()

    for f in flows:
        if f.get("dst_ip"):
            dst_ips.add(f["dst_ip"])
        if f.get("src_ip"):
            src_ips.add(f["src_ip"])
        # Build service string from port/protocol
        port = f.get("dst_port")
        proto = f.get("protocol", "").lower()
        if port and proto in ("tcp", "udp"):
            services.add(f"{proto}-{port}")
        elif f.get("service_group"):
            services.add(f["service_group"])

    from typing import Any
    # Build a single rule entry
    entry: dict[str, Any] = {
        "@name": f"{device_name}-allow",
        "from": {"member": []},
        "to": {"member": []},
        "source": {"member": sorted(src_ips) if src_ips else ["any"]},
        "destination": {"member": sorted(dst_ips) if dst_ips else ["any"]},
        "service": {"member": sorted(services) if services else ["application-default"]},
        "application": {"member": ["any"]},
        "action": "allow",
        "log-start": "yes",
        "log-end": "yes",
        "tag": {"member": ["iot"]},
    }

    target_devices = data.variables.get("target_devices", [])
    if target_devices:
        device_entries = []
        for dev in target_devices:
            dev_entry = {"@name": dev.get("name", "")}
            vsys = dev.get("vsys", [])
            if vsys:
                dev_entry["vsys"] = {"entry": [{"@name": v} for v in vsys]}
            device_entries.append(dev_entry)
        
        if device_entries:
            entry["target"] = {
                "devices": {
                    "entry": device_entries
                }
            }

    return {
        "entry": entry,
        "stats": {
            "allowed_flows": len(flows),
            "unique_destinations": len(dst_ips),
            "unique_services": len(services),
        },
    }
