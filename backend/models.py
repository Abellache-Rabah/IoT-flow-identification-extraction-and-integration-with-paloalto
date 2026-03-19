from pydantic import BaseModel
from typing import Optional


# ---------- Device ----------

class DeviceCreate(BaseModel):
    name: str
    iot_group: str
    requester: str
    homologation_number: str
    device_type: str = ""
    vendor: str = ""
    mac_address: str = ""
    ip_address: str = ""
    description: str = ""
    fan: str = ""
    model: str = ""
    hostname: str = ""
    site: str = ""
    family: str = ""
    serial_number: str = ""


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    iot_group: Optional[str] = None
    requester: Optional[str] = None
    homologation_number: Optional[str] = None
    device_type: Optional[str] = None
    vendor: Optional[str] = None
    mac_address: Optional[str] = None
    ip_address: Optional[str] = None
    description: Optional[str] = None
    fan: Optional[str] = None
    model: Optional[str] = None
    hostname: Optional[str] = None
    site: Optional[str] = None
    family: Optional[str] = None
    serial_number: Optional[str] = None
    status: Optional[str] = None


class DeviceOut(BaseModel):
    id: str
    name: str
    iot_group: str
    requester: str
    homologation_number: str
    device_type: str
    vendor: str
    mac_address: str
    ip_address: str
    description: str
    fan: str
    model: str
    hostname: str
    site: str
    family: str
    serial_number: str
    status: str
    created_at: str
    updated_at: str


# ---------- Capture ----------

class CaptureConfig(BaseModel):
    interface: str = ""
    duration_seconds: int = 3600  # default 1h
    bpf_filter: str = ""


class CaptureOut(BaseModel):
    id: str
    device_id: str
    pcap_path: str
    interface: str
    bpf_filter: str
    duration_seconds: int
    packet_count: int
    file_size: int
    started_at: str
    completed_at: str


# ---------- Flows ----------

class FlowOut(BaseModel):
    id: str
    device_id: str
    capture_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    app_protocol: str
    service_group: str
    dns_name: str
    sni: str
    bytes_total: int
    packets_total: int
    connection_count: int
    allowed: bool
    notes: str


class FlowUpdate(BaseModel):
    allowed: Optional[bool] = None
    notes: Optional[str] = None


class BulkFlowUpdate(BaseModel):
    flow_ids: list[str]
    allowed: bool


# ---------- Rules ----------

class RuleExportConfig(BaseModel):
    format: str = "set_commands"  # set_commands | xml_api | csv
    variables: dict = {}


class RuleExportOut(BaseModel):
    id: str
    device_id: str
    format: str
    variables_json: str
    rules_text: str
    created_at: str
