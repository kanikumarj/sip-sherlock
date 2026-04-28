"""
SIP Parser — Universal parser for ANY vendor SIP log format.

Handles all real-world log formats by scanning for SIP content
ANYWHERE in each line, not just at line starts.

Core strategy: SCAN every line for SIP content ANYWHERE.
Extract SIP from wherever it appears in the log.

Supported formats:
  - Plain SIP (RFC 3261 raw)
  - Cisco CUCM/CUBE debug logs
  - BroadWorks/BroadSoft syslog
  - AudioCodes SBC logs
  - Ribbon/Sonus SBC pipe-delimited
  - Asterisk/FreeSWITCH verbose
  - Kamailio/OpenSIPS trace
  - Wireshark text export
  - Any format with SIP embedded in log lines
"""

from __future__ import annotations
import re
from typing import List, Optional, Tuple, Dict
from models.schemas import SIPMessage, MessageDirection, MessageType


# ─── SIP Methods (RFC 3261 + extensions) ─────────────────────────

SIP_METHODS = [
    "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER",
    "REFER", "NOTIFY", "SUBSCRIBE", "INFO", "UPDATE", "PRACK",
    "MESSAGE", "PUBLISH",
]

METHODS_PATTERN = "|".join(SIP_METHODS)

# ─── Compact SIP headers ─────────────────────────────────────────

COMPACT_HEADERS = {
    'v': 'via', 'f': 'from', 't': 'to', 'm': 'contact',
    'i': 'call-id', 'e': 'content-encoding',
    'l': 'content-length', 'c': 'content-type',
    's': 'subject', 'k': 'supported', 'r': 'require',
    'o': 'allow',
}

# ─── Known SIP headers for validation ────────────────────────────

KNOWN_SIP_HEADERS = {
    'via', 'from', 'to', 'call-id', 'cseq', 'contact',
    'content-type', 'content-length', 'max-forwards',
    'user-agent', 'server', 'allow', 'supported', 'require',
    'record-route', 'route', 'authorization', 'www-authenticate',
    'proxy-authenticate', 'proxy-authorization', 'expires',
    'min-expires', 'subject', 'alert-info', 'reply-to',
    'accept', 'accept-encoding', 'accept-language',
    'warning', 'reason', 'refer-to', 'referred-by',
    'replaces', 'session-expires', 'min-se', 'rack', 'rseq',
    'p-asserted-identity', 'p-preferred-identity', 'p-called-party-id',
    'privacy', 'identity', 'date', 'organization', 'retry-after',
    'timestamp', 'in-reply-to', 'mime-version', 'event',
    'subscription-state', 'content-disposition', 'content-encoding',
    'diversion', 'history-info',
    # compact forms
    'v', 'f', 't', 'm', 'i', 'e', 'l', 'c', 's', 'k', 'r', 'o',
}

# ─── Regex Patterns ──────────────────────────────────────────────

# SIP request line: METHOD sip:... SIP/2.0  (also handles tel:, urn:, IP-only URIs)
RE_SIP_REQUEST = re.compile(
    rf"({METHODS_PATTERN})\s+"
    rf"(?:sip:|sips:|tel:|urn:|\S+@)\S+\s+SIP/2\.0",
    re.IGNORECASE,
)

# Fallback request: METHOD sip:... (without SIP/2.0 suffix)
RE_SIP_REQUEST_RELAXED = re.compile(
    rf"({METHODS_PATTERN})\s+(?:sip:|sips:|tel:|[\d.]+)\S*",
    re.IGNORECASE,
)

# SIP response line: SIP/2.0 CODE REASON
RE_SIP_RESPONSE = re.compile(
    r"SIP/2\.0\s+(\d{3})\s+(.*)",
    re.IGNORECASE,
)

# Timestamp patterns
RE_ISO_TIMESTAMP = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)"
)
RE_CUCM_TIMESTAMP = re.compile(
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{3})?)"
)
RE_TIME_ONLY = re.compile(r"(\d{2}:\d{2}:\d{2}(?:\.\d+)?)")

# Direction keywords
SENT_PATTERNS = [
    re.compile(r'\b(?:sent|send|sending|outgoing|out|tx|transmit|egress)\b', re.I),
    re.compile(r'>>>', re.I),
    re.compile(r'--->', re.I),
    re.compile(r'\|\s*SEND\s*\|', re.I),
]
RECV_PATTERNS = [
    re.compile(r'\b(?:recv|receive|received|receiving|incoming|in|rx|ingress)\b', re.I),
    re.compile(r'<<<', re.I),
    re.compile(r'<---', re.I),
    re.compile(r'\|\s*RECV\s*\|', re.I),
]

# Separator: --- or ===
RE_SEPARATOR = re.compile(r"^[-=]{3,}$")

# Noise lines to skip
NOISE_PATTERNS = [
    # NOTE: empty lines are NOT noise — they are header/body separators
    re.compile(r"^[-=*#]{5,}"),                        # separator lines
    re.compile(r"^\s*\d+\s+bytes\s+", re.I),           # "123 bytes from..."
    re.compile(r"^Frame\s+\d+:", re.I),                # Wireshark frame
    re.compile(r"^Session\s+Initiation\s+Protocol", re.I),  # Wireshark tree
    re.compile(r"^\s*Message\s+Header", re.I),
    re.compile(r"^\s*Request-Line:", re.I),
    re.compile(r"^\s*Status-Line:", re.I),
]


# ─── Core Detection: Find SIP content anywhere in a line ─────────

def _find_sip_start_in_line(line: str) -> Optional[str]:
    """
    Scan a line for SIP request/response content ANYWHERE.
    Returns the SIP first-line content if found, else None.

    This is the KEY FIX: we search for SIP content embedded
    after ANY log prefix — BroadWorks syslog, pipe-delimited,
    tab-prefixed, etc.
    """
    stripped = line.strip()
    if not stripped:
        return None

    # Fast path: line starts with SIP content
    m = RE_SIP_REQUEST.match(stripped)
    if m:
        return stripped

    m = RE_SIP_RESPONSE.match(stripped)
    if m:
        return stripped

    # SCAN: look for SIP content embedded after log prefix
    # Search for SIP response anywhere: "... SIP/2.0 200 OK"
    m = RE_SIP_RESPONSE.search(stripped)
    if m:
        return stripped[m.start():]

    # Search for SIP request anywhere: "... INVITE sip:... SIP/2.0"
    m = RE_SIP_REQUEST.search(stripped)
    if m:
        return stripped[m.start():]

    # Relaxed request (no SIP/2.0 suffix): "... INVITE sip:user@host"
    m = RE_SIP_REQUEST_RELAXED.search(stripped)
    if m:
        return stripped[m.start():]

    # Try after pipe delimiter (Ribbon/generic pipe-delimited logs)
    if '|' in stripped:
        parts = stripped.split('|')
        for part in reversed(parts):
            part = part.strip()
            if RE_SIP_REQUEST.match(part) or RE_SIP_RESPONSE.match(part):
                return part
            if RE_SIP_REQUEST_RELAXED.match(part):
                return part

    return None


def _extract_sip_header_from_line(line: str) -> Optional[str]:
    """
    Extract a SIP header from a log line.
    Handles lines where the header appears after a prefix.
    """
    stripped = line.strip()
    if not stripped:
        return None

    # Direct header at start
    m = re.match(r"^([A-Za-z][A-Za-z0-9\-_]*)\s*:\s*(.+)", stripped)
    if m:
        hname = m.group(1).lower()
        if hname in KNOWN_SIP_HEADERS or (len(hname) == 1 and hname in COMPACT_HEADERS):
            return stripped
        # Accept generic "HeaderName: value" if value looks SIP-ish
        val = m.group(2)
        if re.search(r"sip:|SIP/2\.0|branch=|tag=", val):
            return stripped
        if re.match(r"^\d+$", val.strip()):  # Content-Length: 0
            return stripped

    # Header after log prefix (scan for known header patterns)
    # Try finding "Via:", "From:", "To:" etc. embedded in the line
    for header in ['Via', 'From', 'To', 'Call-ID', 'CSeq', 'Contact',
                   'Content-Type', 'Content-Length', 'Max-Forwards',
                   'User-Agent', 'Warning', 'Reason', 'Authorization',
                   'WWW-Authenticate', 'P-Asserted-Identity', 'Route',
                   'Record-Route', 'Supported', 'Allow', 'Expires',
                   'Server', 'Require', 'Session-Expires', 'Min-SE',
                   'Proxy-Authenticate', 'Proxy-Authorization',
                   'Diversion', 'Privacy', 'Retry-After', 'Refer-To',
                   'Referred-By', 'Replaces', 'Event', 'Accept',
                   'Subscription-State', 'Date', 'Organization',
                   'P-Preferred-Identity', 'P-Called-Party-ID',
                   'History-Info', 'Identity', 'Subject']:
        pattern = re.compile(rf"(?:^|\s)({re.escape(header)}\s*:\s*.+)$", re.IGNORECASE)
        m = pattern.search(stripped)
        if m:
            return m.group(1).strip()

    # Last resort: look for any generic "Header: value" after whitespace
    m = re.search(r'\s([A-Za-z][A-Za-z0-9\-]+\s*:\s*.+)$', stripped)
    if m:
        candidate = m.group(1)
        cm = re.match(r'^([A-Za-z][A-Za-z0-9\-_]*)\s*:\s*(.+)', candidate)
        if cm:
            hname = cm.group(1).lower()
            if hname in KNOWN_SIP_HEADERS:
                return candidate

    return None


def _is_sdp_line(line: str) -> bool:
    """Check if line is SDP content."""
    stripped = line.strip()
    return bool(stripped and len(stripped) >= 2 and stripped[1] == '=' and
                stripped[0] in 'vosiuepcbtrzkam')


def _is_noise(line: str) -> bool:
    """Check if a line is noise to skip."""
    stripped = line.strip()
    for p in NOISE_PATTERNS:
        if p.match(stripped):
            return True
    return False


def _extract_timestamp(line: str) -> Optional[str]:
    """Extract timestamp from a log line."""
    m = RE_ISO_TIMESTAMP.search(line)
    if m:
        return m.group(1)
    m = RE_CUCM_TIMESTAMP.search(line)
    if m:
        return m.group(1)
    m = RE_TIME_ONLY.search(line)
    if m:
        return m.group(1)
    return None


def _detect_direction(lines: List[str]) -> MessageDirection:
    """Detect message direction from context lines."""
    text = ' '.join(lines[-5:]) if lines else ''
    for p in SENT_PATTERNS:
        if p.search(text):
            return MessageDirection.SENT
    for p in RECV_PATTERNS:
        if p.search(text):
            return MessageDirection.RECEIVED
    return MessageDirection.UNKNOWN


# ─── Main Splitter ───────────────────────────────────────────────

def split_sip_messages(raw_text: str) -> List[Tuple[str, Optional[str], MessageDirection]]:
    """
    Split raw text into individual SIP message blocks.
    UNIVERSAL: scans for SIP content anywhere in each line.
    Returns list of (message_text, timestamp, direction) tuples.
    """
    if isinstance(raw_text, bytes):
        raw_text = raw_text.decode("utf-8", errors="replace")

    raw_text = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    lines = raw_text.split("\n")

    messages: List[Tuple[str, Optional[str], MessageDirection]] = []
    current_block: List[str] = []
    current_timestamp: Optional[str] = None
    current_direction = MessageDirection.UNKNOWN
    in_message = False
    in_body = False  # Track if we're in SDP body
    context_lines: List[str] = []  # Recent raw lines for direction detection

    def flush_block():
        nonlocal current_block, current_timestamp, current_direction, in_message, in_body
        if current_block:
            msg_text = "\n".join(current_block).strip()
            if msg_text:
                # Validate: first line must be SIP request or response
                first = msg_text.split("\n")[0].strip()
                if RE_SIP_REQUEST.match(first) or RE_SIP_RESPONSE.match(first) or \
                   RE_SIP_REQUEST_RELAXED.match(first):
                    messages.append((msg_text, current_timestamp, current_direction))
        current_block = []
        current_timestamp = None
        current_direction = MessageDirection.UNKNOWN
        in_message = False
        in_body = False

    i = 0
    while i < len(lines):
        raw_line = lines[i]
        stripped = raw_line.strip()
        i += 1

        # Track context for direction detection
        context_lines.append(raw_line)
        if len(context_lines) > 10:
            context_lines.pop(0)

        # ── Skip noise lines ──
        if _is_noise(stripped):
            continue

        # ── Separator lines end current block ──
        if RE_SEPARATOR.match(stripped):
            flush_block()
            continue

        # ── Empty line handling ──
        if not stripped:
            if in_message and not in_body:
                # Empty line inside a SIP message = header/body separator
                in_body = True
                current_block.append("")
            elif in_body:
                # Empty line in body — might be end of SDP
                current_block.append("")
            continue

        # ── Try to find SIP start line ──
        sip_start = _find_sip_start_in_line(stripped)
        if sip_start:
            # Extract metadata from the prefix part
            ts = _extract_timestamp(raw_line)
            direction = _detect_direction([raw_line])

            # Save previous block
            if in_message:
                flush_block()

            # Start new block
            in_message = True
            in_body = False
            current_block = [sip_start]
            current_timestamp = ts or current_timestamp
            if direction != MessageDirection.UNKNOWN:
                current_direction = direction
            else:
                # Try direction from recent context
                ctx_direction = _detect_direction(context_lines)
                if ctx_direction != MessageDirection.UNKNOWN:
                    current_direction = ctx_direction
            continue

        # ── Inside a SIP message: collect headers, SDP ──
        if in_message:
            if in_body:
                # In SDP body — accept SDP lines
                if _is_sdp_line(stripped):
                    current_block.append(stripped)
                else:
                    # Non-SDP content in body — try extracting SIP header
                    # (some logs interleave metadata in body)
                    hdr = _extract_sip_header_from_line(stripped)
                    if hdr:
                        current_block.append(hdr)
                    # Otherwise skip noise in body
            else:
                # In headers — extract SIP header content
                hdr = _extract_sip_header_from_line(stripped)
                if hdr:
                    current_block.append(hdr)
                elif stripped.startswith((" ", "\t")) and current_block:
                    # Header folding (RFC 3261 §7.3.1)
                    current_block[-1] += " " + stripped.strip()
                else:
                    # Not a header — might be a log prefix/metadata line
                    # Extract direction/timestamp but don't add to block
                    ts = _extract_timestamp(raw_line)
                    if ts and not current_timestamp:
                        current_timestamp = ts
                    direction = _detect_direction([raw_line])
                    if direction != MessageDirection.UNKNOWN:
                        current_direction = direction
            continue

        # ── Not in a message — extract metadata for next message ──
        ts = _extract_timestamp(raw_line)
        if ts:
            current_timestamp = ts
        direction = _detect_direction([raw_line])
        if direction != MessageDirection.UNKNOWN:
            current_direction = direction

    # Flush last block
    flush_block()

    return messages


# ─── Single Message Parser ───────────────────────────────────────

def parse_single_message(
    raw: str,
    index: int,
    timestamp: Optional[str] = None,
    direction: MessageDirection = MessageDirection.UNKNOWN,
) -> SIPMessage:
    """Parse a single SIP message string into a SIPMessage object."""
    lines = raw.strip().split("\n")
    first_line = lines[0].strip()

    msg = SIPMessage(
        index=index,
        timestamp=timestamp,
        direction=direction,
        raw_message=raw.strip(),
    )

    # Determine request or response
    req_match = RE_SIP_REQUEST.match(first_line) or RE_SIP_REQUEST_RELAXED.match(first_line)
    resp_match = RE_SIP_RESPONSE.match(first_line)

    if req_match:
        msg.type = MessageType.REQUEST
        parts = first_line.split()
        msg.method = parts[0].upper()
        # Extract request URI (the second token): INVITE sip:user@host SIP/2.0
        if len(parts) >= 2:
            msg.request_uri = parts[1]
    elif resp_match:
        msg.type = MessageType.RESPONSE
        msg.response_code = int(resp_match.group(1))
        msg.response_text = resp_match.group(2).strip()

    # Split into headers and body
    header_lines: List[str] = []
    body_lines: List[str] = []
    in_body = False

    for line in lines[1:]:
        if not in_body and line.strip() == "":
            in_body = True
            continue
        if in_body:
            body_lines.append(line)
        else:
            # RFC 3261 §7.3.1: Header folding
            if (line.startswith(" ") or line.startswith("\t")) and header_lines:
                header_lines[-1] += " " + line.strip()
            else:
                header_lines.append(line.strip())

    # Parse individual headers
    for hdr in header_lines:
        colon_idx = hdr.find(":")
        if colon_idx < 1:
            continue

        name = hdr[:colon_idx].strip().lower()
        val = hdr[colon_idx + 1:].strip()

        # Expand compact header forms
        if len(name) == 1 and name in COMPACT_HEADERS:
            name = COMPACT_HEADERS[name]

        if name == "from":
            msg.from_header = val
        elif name == "to":
            msg.to_header = val
        elif name == "call-id":
            msg.call_id = val
        elif name == "cseq":
            msg.cseq = val
            # Extract method from CSeq for ALL message types
            cseq_parts = val.split()
            if len(cseq_parts) >= 2:
                msg.cseq_method = cseq_parts[1].upper()
                # For responses, also set method from CSeq
                if msg.type == MessageType.RESPONSE:
                    msg.method = cseq_parts[1].upper()
        elif name == "via":
            msg.via_headers.append(val)
        elif name == "contact":
            msg.contact = val
        elif name in ("user-agent", "server"):
            msg.user_agent = val

    # Extract SDP body
    if body_lines:
        body_text = "\n".join(body_lines).strip()
        if body_text and ("v=0" in body_text or "m=audio" in body_text
                          or "m=video" in body_text or "m=image" in body_text):
            msg.sdp_body = body_text

    return msg


# ─── Public API ──────────────────────────────────────────────────

def parse_sip_text(raw_text: str) -> List[SIPMessage]:
    """
    Parse raw SIP text (ANY format, ANY vendor) into SIPMessage objects.
    Messages are returned in order of appearance.

    Core strategy: scan for SIP content ANYWHERE in each line,
    not just at line starts. This handles BroadWorks syslog,
    pipe-delimited SBC logs, and any vendor format.
    """
    if not raw_text or not raw_text.strip():
        return []

    # Step 1: Normal extraction
    blocks = split_sip_messages(raw_text)

    # Step 2: If nothing found, try aggressive fallback
    if not blocks:
        blocks = _aggressive_fallback_extraction(raw_text)

    # Step 3: Parse each block
    messages: List[SIPMessage] = []
    for i, (msg_text, timestamp, direction) in enumerate(blocks):
        msg = parse_single_message(msg_text, index=i, timestamp=timestamp, direction=direction)
        messages.append(msg)

    return messages


def _aggressive_fallback_extraction(text: str) -> List[Tuple[str, Optional[str], MessageDirection]]:
    """
    Last-resort extraction: scan every line for ANY SIP content.
    Joins consecutive SIP-looking lines into messages.
    Used when normal extraction finds nothing.
    """
    blocks: List[Tuple[str, Optional[str], MessageDirection]] = []
    current: List[str] = []
    current_ts: Optional[str] = None
    current_dir = MessageDirection.UNKNOWN

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Try to find SIP request anywhere in this line
        for method in SIP_METHODS:
            pattern = re.compile(
                rf'(?:^|\s)({method}\s+(?:sip:|sips:|tel:)\S+(?:\s+SIP/2\.0)?)',
                re.IGNORECASE
            )
            m = pattern.search(stripped)
            if m:
                if current:
                    msg_text = '\n'.join(current)
                    first = msg_text.split('\n')[0].strip()
                    if RE_SIP_REQUEST.match(first) or RE_SIP_RESPONSE.match(first) or \
                       RE_SIP_REQUEST_RELAXED.match(first):
                        blocks.append((msg_text, current_ts, current_dir))
                    current = []
                current = [m.group(1).strip()]
                current_ts = _extract_timestamp(line)
                current_dir = _detect_direction([line])
                break

        # Check for SIP response anywhere
        resp_m = re.search(r'(SIP/2\.0\s+\d{3}\s+\w.*)', stripped, re.IGNORECASE)
        if resp_m and not current:
            current = [resp_m.group(1).strip()]
            current_ts = _extract_timestamp(line)
            current_dir = _detect_direction([line])
            continue
        elif resp_m and current:
            # Save current block and start new one
            msg_text = '\n'.join(current)
            first = msg_text.split('\n')[0].strip()
            if RE_SIP_REQUEST.match(first) or RE_SIP_RESPONSE.match(first) or \
               RE_SIP_REQUEST_RELAXED.match(first):
                blocks.append((msg_text, current_ts, current_dir))
            current = [resp_m.group(1).strip()]
            current_ts = _extract_timestamp(line)
            current_dir = _detect_direction([line])
            continue

        # SIP header or SDP line → add to current block
        if current:
            hdr = _extract_sip_header_from_line(stripped)
            if hdr:
                current.append(hdr)
            elif _is_sdp_line(stripped):
                current.append(stripped)

    if current:
        msg_text = '\n'.join(current)
        first = msg_text.split('\n')[0].strip()
        if RE_SIP_REQUEST.match(first) or RE_SIP_RESPONSE.match(first) or \
           RE_SIP_REQUEST_RELAXED.match(first):
            blocks.append((msg_text, current_ts, current_dir))

    return blocks


def group_by_call_id(messages: List[SIPMessage]) -> Dict[str, List[SIPMessage]]:
    """Group messages by Call-ID."""
    groups: Dict[str, List[SIPMessage]] = {}
    for msg in messages:
        cid = msg.call_id or "unknown"
        if cid not in groups:
            groups[cid] = []
        groups[cid].append(msg)
    return groups


def select_primary_call(groups: Dict[str, List[SIPMessage]]) -> List[SIPMessage]:
    """Select the most interesting call from grouped calls."""
    if not groups:
        return []

    def score_call(msgs: List[SIPMessage]) -> int:
        s = 0
        for m in msgs:
            if m.response_code and m.response_code >= 500:
                s += 100
            elif m.response_code and m.response_code >= 400 and m.response_code != 487:
                s += 50
            elif m.response_code and m.response_code == 487:
                s += 5
        s += len(msgs)
        return s

    best_cid = max(groups, key=lambda cid: score_call(groups[cid]))
    return groups[best_cid]


def get_primary_call(messages: List[SIPMessage]) -> List[SIPMessage]:
    """
    From a multi-call log, return the messages of the
    most relevant call (failed call if exists, else longest).
    """
    if not messages:
        return []

    groups = group_by_call_id(messages)

    if len(groups) == 1:
        return messages

    return select_primary_call(groups)


def get_all_calls_summary(groups: Dict[str, List[SIPMessage]]) -> List[Dict]:
    """Return a summary of all calls found in the log."""
    summaries = []
    for cid, msgs in groups.items():
        invite = next((m for m in msgs if m.method == "INVITE" and m.type == MessageType.REQUEST), None)
        failure = next((m for m in msgs if m.response_code and m.response_code >= 400), None)

        summaries.append({
            "call_id": cid,
            "message_count": len(msgs),
            "calling_party": _extract_uri(invite.from_header) if invite else "Unknown",
            "called_party": _extract_uri(invite.to_header) if invite else "Unknown",
            "has_failure": failure is not None,
            "failure_code": failure.response_code if failure else None,
            "method": invite.method if invite else msgs[0].method if msgs else "UNKNOWN",
        })
    summaries.sort(key=lambda s: (not s["has_failure"], -s["message_count"]))
    return summaries


def _extract_uri(header: str) -> str:
    """Extract a clean URI or phone number from a SIP From/To header."""
    if not header:
        return ""
    match = re.search(r"<sip:([^>]+)>", header)
    if match:
        uri = match.group(1)
        user = uri.split("@")[0]
        return user
    return header.strip()
