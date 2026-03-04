from pathlib import Path
from services.zeek_service import get_connections, get_dns_queries, get_ssl_connections, get_ot_logs

# Well-known port -> service group mapping
SERVICE_GROUPS = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    123: "NTP",
    80: "HTTP",
    443: "HTTPS/TLS",
    8443: "HTTPS/TLS",
    8080: "HTTP",
    1883: "MQTT",
    8883: "MQTT/TLS",
    5683: "CoAP",
    502: "Modbus",
    20000: "DNP3",
    47808: "BACnet",
    102: "S7comm",
    44818: "EtherNet/IP",
    2222: "EtherNet/IP",
    161: "SNMP",
    162: "SNMP",
    514: "Syslog",
    6514: "Syslog/TLS",
    22: "SSH",
    2404: "IEC 60870-5-104",
}


def classify_service_group(port: int, service: str, proto: str) -> str:
    """Classify a flow into a service group."""
    # Check by service name first (from Zeek)
    svc_lower = service.lower() if service else ""
    if svc_lower in ("dns", "domain"):
        return "DNS"
    if svc_lower == "ntp":
        return "NTP"
    if svc_lower == "dhcp":
        return "DHCP"
    if svc_lower == "http":
        return "HTTP"
    if svc_lower in ("ssl", "tls"):
        return "HTTPS/TLS"
    if svc_lower == "ssh":
        return "SSH"
    if svc_lower == "modbus":
        return "Modbus"
    if svc_lower == "dnp3":
        return "DNP3"
    if svc_lower == "bacnet":
        return "BACnet"
    if svc_lower == "mqtt":
        return "MQTT"

    # Check by port
    if port in SERVICE_GROUPS:
        return SERVICE_GROUPS[port]

    # Check by protocol
    if proto == "icmp":
        return "ICMP"

    return "Other"


def extract_flows(output_dir: str, device_ip: str = "") -> list[dict]:
    """Extract and aggregate unique flows from Zeek conn.log."""
    connections = get_connections(output_dir)
    dns_records = get_dns_queries(output_dir)
    ssl_records = get_ssl_connections(output_dir)
    ot_logs = get_ot_logs(output_dir)

    # Build DNS lookup: IP -> list of queried names
    dns_map: dict[str, set] = {}
    for d in dns_records:
        answers = d.get("answers", "")
        query = d.get("query", "")
        if answers and query:
            for ip in str(answers).split(","):
                ip = ip.strip()
                if ip and ip != "-":
                    dns_map.setdefault(ip, set()).add(query)

    # Build SNI lookup: (src, dst, dst_port) -> SNI
    sni_map: dict[tuple, str] = {}
    for s in ssl_records:
        key = (
            s.get("id.orig_h", ""),
            s.get("id.resp_h", ""),
            s.get("id.resp_p", ""),
        )
        sni = s.get("server_name", "")
        if sni and sni != "-":
            sni_map[key] = sni

    # Build OT protocol lookup: (src, dst, dst_port) -> protocol name
    ot_map: dict[tuple, str] = {}
    for proto_name, records in ot_logs.items():
        for r in records:
            key = (
                r.get("id.orig_h", ""),
                r.get("id.resp_h", ""),
                r.get("id.resp_p", ""),
            )
            ot_map[key] = proto_name

    # Aggregate flows by (src, dst, dst_port, proto)
    flow_agg: dict[tuple, dict] = {}
    for c in connections:
        src_ip = c.get("id.orig_h", "")
        dst_ip = c.get("id.resp_h", "")
        src_port = 0  # don't aggregate by src port (ephemeral)
        dst_port_str = c.get("id.resp_p", "0")
        try:
            dst_port = int(dst_port_str)
        except ValueError:
            dst_port = 0

        proto = c.get("proto", "")
        service = c.get("service", "-")
        if service == "-":
            service = ""

        key = (src_ip, dst_ip, dst_port, proto)

        try:
            orig_bytes = int(c.get("orig_bytes", 0) or 0)
            resp_bytes = int(c.get("resp_bytes", 0) or 0)
            orig_pkts = int(c.get("orig_pkts", 0) or 0)
            resp_pkts = int(c.get("resp_pkts", 0) or 0)
        except ValueError:
            orig_bytes = resp_bytes = orig_pkts = resp_pkts = 0

        conn_key = (src_ip, dst_ip, dst_port_str)
        sni = sni_map.get(conn_key, "")
        dns_names = dns_map.get(dst_ip, set())
        ot_proto = ot_map.get(conn_key, "")

        app_protocol = ot_proto or service
        service_group = classify_service_group(dst_port, service, proto)

        if key in flow_agg:
            f = flow_agg[key]
            f["bytes_total"] += orig_bytes + resp_bytes
            f["packets_total"] += orig_pkts + resp_pkts
            f["connection_count"] += 1
            if sni and not f["sni"]:
                f["sni"] = sni
            if dns_names:
                f["dns_name"] = ", ".join(dns_names)
            if app_protocol and not f["app_protocol"]:
                f["app_protocol"] = app_protocol
        else:
            flow_agg[key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": 0,
                "dst_port": dst_port,
                "protocol": proto,
                "app_protocol": app_protocol,
                "service_group": service_group,
                "dns_name": ", ".join(dns_names) if dns_names else "",
                "sni": sni,
                "bytes_total": orig_bytes + resp_bytes,
                "packets_total": orig_pkts + resp_pkts,
                "connection_count": 1,
            }

    flows = list(flow_agg.values())

    # Sort: device flows first (if device_ip known), then by bytes
    if device_ip:
        flows.sort(
            key=lambda f: (
                0 if f["src_ip"] == device_ip else 1,
                -f["bytes_total"],
            )
        )
    else:
        flows.sort(key=lambda f: -f["bytes_total"])

    return flows
