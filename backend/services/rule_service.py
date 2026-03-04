import json
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "paloalto"


def _get_jinja_env():
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def generate_rules(flows: list[dict], variables: dict, fmt: str = "set_commands") -> str:
    """Generate Palo Alto firewall rules from allowed flows."""
    allowed_flows = [f for f in flows if f.get("allowed", False)]
    if not allowed_flows:
        return "# No allowed flows to generate rules for."

    # Default variables
    default_vars = {
        "device_zone": "IoT",
        "server_zone": "Trust",
        "internet_zone": "Untrust",
        "vsys": "vsys1",
        "device_name": "iot-device",
        "tag": "iot-onboarding",
        "firewall_context": "PA-DEFAULT",
        "address_prefix": "IoT",
        "rule_prefix": "IoT",
    }
    merged_vars = {**default_vars, **variables}

    # Prepare flow data for templates
    rules_data = _prepare_rules_data(allowed_flows, merged_vars)

    env = _get_jinja_env()

    if fmt == "xml_api":
        template = env.get_template("xml_api.j2")
    elif fmt == "csv":
        return _generate_csv(rules_data, merged_vars)
    else:
        template = env.get_template("set_commands.j2")

    return template.render(
        rules=rules_data,
        vars=merged_vars,
        flows=allowed_flows,
    )


def _prepare_rules_data(flows: list[dict], variables: dict) -> list[dict]:
    """Prepare structured rule data from flows."""
    rules = []
    prefix = variables.get("rule_prefix", "IoT")
    device_name = variables.get("device_name", "device")

    # Group flows by service_group for cleaner rules
    groups: dict[str, list[dict]] = {}
    for f in flows:
        group = f.get("service_group", "Other")
        groups.setdefault(group, [])
        groups[group].append(f)

    rule_idx = 1
    for group_name, group_flows in groups.items():
        # Collect unique destinations and ports
        destinations = set()
        services = set()
        protocols = set()

        for f in group_flows:
            dst = f.get("dns_name") or f.get("sni") or f.get("dst_ip", "")
            destinations.add(dst)
            if f.get("dst_port"):
                proto = f.get("protocol", "tcp").lower()
                services.add(f"{proto}/{f['dst_port']}")
                protocols.add(proto)

        rule = {
            "index": rule_idx,
            "name": f"{prefix}-{device_name}-{group_name}-{rule_idx}",
            "service_group": group_name,
            "destinations": sorted(destinations),
            "destination_ips": sorted(set(f.get("dst_ip", "") for f in group_flows)),
            "services": sorted(services),
            "protocols": sorted(protocols),
            "ports": sorted(set(f.get("dst_port", 0) for f in group_flows)),
            "notes": "; ".join(set(f.get("notes", "") for f in group_flows if f.get("notes"))),
        }
        rules.append(rule)
        rule_idx += 1

    return rules


def _generate_csv(rules: list[dict], variables: dict) -> str:
    """Generate CSV format for documentation."""
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Rule Name", "Service Group", "Source Zone", "Dest Zone",
        "Destination IPs", "Services", "Action", "Tag", "Notes",
        "Firewall Context",
    ])

    for r in rules:
        writer.writerow([
            r["name"],
            r["service_group"],
            variables.get("device_zone", "IoT"),
            variables.get("server_zone", "Trust"),
            "; ".join(r["destination_ips"]),
            "; ".join(r["services"]),
            "allow",
            variables.get("tag", "iot-onboarding"),
            r.get("notes", ""),
            variables.get("firewall_context", ""),
        ])

    return output.getvalue()
