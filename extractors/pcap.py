from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapReader

from core.packets import Packet, PacketStatus

def _decode(value):
    """Convert Scapy byte values into readable strings."""
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip("\x00")

    return str(value)


def _timestamp(value):
    """Convert a packet timestamp into an ISO 8601 UTC timestamp."""
    if value is None:
        return None

    return datetime.fromtimestamp(
        float(value),
        tz=timezone.utc,
    ).isoformat()


def _packet_details(pkt, number):
    """Extract metadata from an individual captured packet."""

    layers = []
    current_layer = pkt

    while current_layer:
        layer_name = current_layer.__class__.__name__

        if layer_name not in layers:
            layers.append(layer_name)

        current_layer = current_layer.payload

        if current_layer.__class__.__name__ == "NoPayload":
            break

    details = {
        "number": number,
        "timestamp": _timestamp(getattr(pkt, "time", None)),
        "length": len(pkt),
        "wire_length": getattr(pkt, "wirelen", None),
        "layers": layers,
        "source_mac": None,
        "destination_mac": None,
        "source_ip": None,
        "destination_ip": None,
        "protocol": "OTHER",
        "source_port": None,
        "destination_port": None,
        "tcp_flags": None,
        "dns": None,
    }

    if pkt.haslayer(Ether):
        ethernet = pkt[Ether]
        details["source_mac"] = ethernet.src
        details["destination_mac"] = ethernet.dst

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        details["source_ip"] = arp.psrc
        details["destination_ip"] = arp.pdst
        details["protocol"] = "ARP"

    elif pkt.haslayer(IP):
        ip = pkt[IP]
        details["source_ip"] = ip.src
        details["destination_ip"] = ip.dst
        details["protocol"] = "IP"

    elif pkt.haslayer(IPv6):
        ipv6 = pkt[IPv6]
        details["source_ip"] = ipv6.src
        details["destination_ip"] = ipv6.dst
        details["protocol"] = "IPv6"

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        details["protocol"] = "TCP"
        details["source_port"] = tcp.sport
        details["destination_port"] = tcp.dport
        details["tcp_flags"] = str(tcp.flags)

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        details["protocol"] = "UDP"
        details["source_port"] = udp.sport
        details["destination_port"] = udp.dport

    elif pkt.haslayer(ICMP):
        details["protocol"] = "ICMP"

    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        dns_details = {
            "id": dns.id,
            "is_response": bool(dns.qr),
            "opcode": dns.opcode,
            "response_code": dns.rcode,
            "question_count": dns.qdcount,
            "answer_count": dns.ancount,
        }

        if pkt.haslayer(DNSQR):
            question = pkt[DNSQR]
            dns_details["query_name"] = _decode(question.qname)
            dns_details["query_type"] = question.qtype

        details["dns"] = dns_details

    return details


def pcapextract(packet: Packet) -> Packet:
    """
    Extract packet metadata from a PCAP or PCAPNG capture.

    Input:
        A filesystem path or bytes containing a capture.

    Output:
        Capture metadata, protocol counts, endpoint counts,
        and individual packet summaries.
    """

    result = packet.child(
        stage="extraction",
        artefact_type="pcap",
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
                "PCAP input must be a file path or bytes."
            )

        packets = []
        protocol_counts = Counter()
        endpoint_counts = Counter()
        total_bytes = 0

        for number, pkt in enumerate(reader, start=1):
            details = _packet_details(pkt, number)
            packets.append(details)

            protocol_counts[details["protocol"]] += 1
            total_bytes += details["length"]

            for field in ("source_ip", "destination_ip"):
                address = details[field]

                if address:
                    endpoint_counts[address] += 1

        result.data = {
            "capture": {
                "packet_count": len(packets),
                "total_captured_bytes": total_bytes,
            },
            "protocol_counts": dict(protocol_counts),
            "endpoint_counts": dict(endpoint_counts),
            "packets": packets,
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="PCAP_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.pcap",
        )

    except (TypeError, ValueError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="INVALID_PCAP_INPUT",
            message=str(exc),
            component="extractors.pcap",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="PCAP_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.pcap",
        )

    finally:
        if reader is not None:
            reader.close()

    return result