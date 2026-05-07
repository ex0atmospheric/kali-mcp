import xml.etree.ElementTree as ET


def parse(xml_output: str) -> dict:
    result: dict = {"hosts": {}}

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return result

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        hostnames = [
            hn.get("name", "")
            for hn in host.findall(".//hostname")
            if hn.get("name")
        ]

        ports: dict = {}
        for port_el in host.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = port_el.get("portid", "")
            svc = port_el.find("service")
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            ports[portid] = {
                "state": "open",
                "service": svc.get("name", "") if svc is not None else "",
                "version": f"{product} {version}".strip(),
            }

        os_el = host.find(".//osmatch")
        os_name = os_el.get("name") if os_el is not None else None

        result["hosts"][ip] = {
            "ports": ports,
            "os": os_name,
            "hostnames": hostnames,
        }

    return result
