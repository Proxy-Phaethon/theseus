from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

from core.packets import Packet, PacketStatus

def _timestamp(value):
    if value is None:
        return None

    return datetime.fromtimestamp(
        float(value),
        tz=timezone.utc,
    ).isoformat()

def _get_packet_endpoints(pkt):
    """Return IP endpoints and transport details for a packet."""

    if pkt.haslayer(IP):
        source = pkt[IP].src
        destination = pkt[IP].dst
        ip_version = 4

    elif pkt.haslayer(IPv6):
        source = pkt[IPv6].src
        destination = pkt[IPv6].dst
        ip_version = 6

    else:
        return None

    if pkt.haslayer(TCP):
        transport = "TCP"
        source_port = int(pkt[TCP].sport)
        destination_port = int(pkt[TCP].dport)
        flags = str(pkt[TCP].flags)
        extra = None

    elif pkt.haslayer(UDP):
        transport = "UDP"
        source_port = int(pkt[UDP].sport)
        destination_port = int(pkt[UDP].dport)
        flags = None
        extra = None

    elif pkt.haslayer(ICMP):
        transport = "ICMP"
        source_port = None
        destination_port = None
        flags = None
        extra = {
            "type": int(pkt[ICMP].type),
            "code": int(pkt[ICMP].code),
        }

    else:
        transport = str(
            pkt[IP].proto if ip_version == 4 else pkt[IPv6].nh
        )
        source_port = None
        destination_port = None
        flags = None
        extra = None

    source_endpoint = (source, source_port)
    destination_endpoint = (destination, destination_port)

    # Canonical ordering makes both directions share one flow.
    endpoints = tuple(sorted((source_endpoint, destination_endpoint)))

    return {
        "ip_version": ip_version,
        "protocol": transport,
        "source": source_endpoint,
        "destination": destination_endpoint,
        "endpoints": endpoints,
        "flags": flags,
        "extra": extra,
    }

def flowextract(packet: Packet) -> Packet:
    """
    Group captured IP packets into bidirectional network flows.

    Input:
        A filesystem path or bytes containing a PCAP/PCAPNG capture.

    Output:
        Flow summaries containing endpoints, packet and byte counts,
        timestamps, direction counts, and TCP flag counts.
    """

    result = packet.child(
        stage="extraction",
        artefact_type="flow",
        status=PacketStatus.RUNNING,
    )

    reader = None

    try:
        source = packet.input

        if isinstance(source, bytes):
            reader = PcapReader(BytesIO(source))

        elif isinstance(source, str):
            path = Path(source.strip()).expanduser()

            if not path.exists():
                raise FileNotFoundError(
                    f"Capture file does not exist: {path}"
                )

            if not path.is_file():
                raise ValueError("Input must be a capture file.")

            reader = PcapReader(str(path))

        else:
            raise TypeError(
                "Flow input must be a file path or bytes."
            )

        flows = {}
        total_packets = 0
        skipped_packets = 0
        total_bytes = 0

        for pkt in reader:
            total_packets += 1

            details = _get_packet_endpoints(pkt)

            if details is None:
                skipped_packets += 1
                continue

            protocol = details["protocol"]
            endpoints = details["endpoints"]
            extra = details["extra"]

            flow_key = (
                details["ip_version"],
                protocol,
                endpoints,
                extra.get("type") if extra else None,
                extra.get("code") if extra else None,
            )

            timestamp = float(pkt.time)
            packet_length = len(pkt)

            if flow_key not in flows:
                flows[flow_key] = {
                    "ip_version": details["ip_version"],
                    "protocol": protocol,
                    "endpoint_a": {
                        "address": endpoints[0][0],
                        "port": endpoints[0][1],
                    },
                    "endpoint_b": {
                        "address": endpoints[1][0],
                        "port": endpoints[1][1],
                    },
                    "packet_count": 0,
                    "total_bytes": 0,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "direction_a_to_b": 0,
                    "direction_b_to_a": 0,
                    "tcp_flag_counts": Counter(),
                    "icmp": extra,
                }

            flow = flows[flow_key]

            flow["packet_count"] += 1
            flow["total_bytes"] += packet_length
            flow["first_seen"] = min(flow["first_seen"], timestamp)
            flow["last_seen"] = max(flow["last_seen"], timestamp)

            if details["source"] == endpoints[0]:
                flow["direction_a_to_b"] += 1
            else:
                flow["direction_b_to_a"] += 1

            if details["flags"]:
                for flag in details["flags"]:
                    flow["tcp_flag_counts"][flag] += 1

            total_bytes += packet_length

        flow_results = []

        for flow in flows.values():
            flow_results.append({
                **{
                    key: value
                    for key, value in flow.items()
                    if key != "tcp_flag_counts"
                },
                "first_seen": _timestamp(flow["first_seen"]),
                "last_seen": _timestamp(flow["last_seen"]),
                "tcp_flag_counts": dict(flow["tcp_flag_counts"]),
            })

        result.data = {
            "capture": {
                "packet_count": total_packets,
                "flow_count": len(flow_results),
                "skipped_packets": skipped_packets,
                "total_captured_bytes": total_bytes,
            },
            "flows": flow_results,
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="PCAP_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.flow",
        )

    except (TypeError, ValueError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="INVALID_FLOW_INPUT",
            message=str(exc),
            component="extractors.flow",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="FLOW_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.flow",
        )

    finally:
        if reader is not None:
            reader.close()

    return result