"""
PCAP Parser — extracts SIP messages from .pcap / .pcapng files.
Uses dpkt for packet decoding. Filters UDP/TCP on ports 5060/5061.
"""

from __future__ import annotations
import io
import struct
from typing import List
from models.schemas import SIPMessage
from parser.sip_parser import parse_sip_text


SIP_PORTS = {5060, 5061}


def extract_sip_from_pcap(file_bytes: bytes) -> List[SIPMessage]:
    """
    Read a PCAP file from bytes and extract SIP messages.
    Returns parsed SIPMessage list in chronological order.
    """
    try:
        import dpkt
    except ImportError:
        raise RuntimeError("dpkt library is required for PCAP parsing. Install with: pip install dpkt")

    sip_payloads: List[str] = []

    f = io.BytesIO(file_bytes)

    try:
        pcap = dpkt.pcap.Reader(f)
    except ValueError:
        # Try pcapng format
        f.seek(0)
        try:
            pcap = dpkt.pcapng.Reader(f)
        except Exception:
            raise ValueError("Unable to read file as PCAP or PCAPNG format")

    for timestamp, buf in pcap:
        try:
            payload = _extract_sip_payload(buf)
            if payload:
                sip_payloads.append(payload)
        except Exception:
            # Skip malformed packets silently
            continue

    if not sip_payloads:
        return []

    # Join all SIP payloads separated by '---' for the text parser
    combined = "\n---\n".join(sip_payloads)
    return parse_sip_text(combined)


def _extract_sip_payload(buf: bytes) -> str | None:
    """
    Extract SIP payload from a raw packet buffer.
    Handles Ethernet → IP → UDP/TCP → SIP.
    """
    try:
        import dpkt
    except ImportError:
        return None

    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        # Try raw IP
        try:
            ip = dpkt.ip.IP(buf)
        except Exception:
            return None
    else:
        if not isinstance(eth.data, dpkt.ip.IP):
            return None
        ip = eth.data

    # Check for UDP or TCP
    if isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        if udp.sport not in SIP_PORTS and udp.dport not in SIP_PORTS:
            return None
        payload = udp.data
    elif isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        if tcp.sport not in SIP_PORTS and tcp.dport not in SIP_PORTS:
            return None
        payload = tcp.data
    else:
        return None

    if not payload:
        return None

    # Try to decode as UTF-8 text
    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return None

    # Quick check: does it look like SIP?
    if not text.strip():
        return None

    first_line = text.strip().split("\n")[0]
    if "SIP/2.0" in first_line:
        return text.strip()

    return None
