"""
SIP Knowledge Base — Embedded platform-specific knowledge for deterministic analysis.

Contains comprehensive SIP error code definitions, codec mappings,
platform-specific knowledge (CUCM, CUBE, AudioCodes, Teams, carriers),
and ISDN disconnect cause code mappings.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Tuple

# ─── IANA Codec Payload Type Mapping ─────────────────────────────

STATIC_PAYLOAD_TYPES: Dict[int, str] = {
    0: "PCMU",     # G.711 μ-law (North America)
    3: "GSM",
    4: "G723",
    8: "PCMA",     # G.711 A-law (Europe/ROW)
    9: "G722",     # HD Voice (16kHz)
    13: "CN",      # Comfort Noise
    18: "G729",    # Compressed (8kbps)
}

CODEC_FRIENDLY_NAMES: Dict[str, str] = {
    "PCMU": "G.711 μ-law",
    "PCMA": "G.711 A-law",
    "G722": "G.722 HD Voice",
    "G729": "G.729",
    "G723": "G.723.1",
    "OPUS": "Opus",
    "ILBC": "iLBC",
    "AMR": "AMR",
    "CN": "Comfort Noise",
    "TELEPHONE-EVENT": "DTMF (RFC 2833)",
}

CODEC_BITRATES: Dict[str, str] = {
    "PCMU": "64 kbps",
    "PCMA": "64 kbps",
    "G722": "64 kbps",
    "G729": "8 kbps",
    "G723": "6.3/5.3 kbps",
    "OPUS": "6-510 kbps (variable)",
    "ILBC": "15.2/13.3 kbps",
}


# ─── SIP Response Code Full Knowledge ────────────────────────────

SIP_RESPONSE_KNOWLEDGE: Dict[int, Dict] = {
    # 1xx Provisional
    100: {
        "name": "Trying",
        "class": "PROVISIONAL",
        "is_error": False,
        "description": "Server processing the request",
        "problem_if": "Missing entirely may indicate firewall blocking",
    },
    180: {
        "name": "Ringing",
        "class": "PROVISIONAL",
        "is_error": False,
        "description": "Destination phone is ringing",
        "problem_if": "Never followed by 200 OK or failure response — ring no answer",
    },
    181: {"name": "Call Is Being Forwarded", "class": "PROVISIONAL", "is_error": False, "description": "Call diverted"},
    182: {"name": "Queued", "class": "PROVISIONAL", "is_error": False, "description": "Call placed in queue (ACD/CC)"},
    183: {
        "name": "Session Progress",
        "class": "PROVISIONAL",
        "is_error": False,
        "description": "Early media (ringback from PSTN)",
        "problem_if": "183 with SDP but no audio indicates SDP mismatch",
    },

    # 2xx Success
    200: {
        "name": "OK",
        "class": "SUCCESS",
        "is_error": False,
        "description": "Request accepted / call answered",
        "problem_if": "200 OK to INVITE without ACK causes call to hang",
    },
    202: {"name": "Accepted", "class": "SUCCESS", "is_error": False, "description": "Used for REFER/SUBSCRIBE"},

    # 3xx Redirection
    301: {"name": "Moved Permanently", "class": "REDIRECTION", "is_error": False, "description": "Number ported or permanently forwarded"},
    302: {"name": "Moved Temporarily", "class": "REDIRECTION", "is_error": False, "description": "Temporary forward — follow Contact header"},
    380: {"name": "Alternative Service", "class": "REDIRECTION", "is_error": False, "description": "Try alternative method/service"},

    # 4xx Client Errors
    400: {
        "name": "Bad Request",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "HIGH",
        "failure_layer": "SIGNALING",
        "description": "Malformed SIP message",
        "common_causes": [
            "Invalid header syntax (missing space, wrong format)",
            "Missing required headers (To, From, Call-ID, CSeq, Via)",
            "Content-Length mismatch with actual body size",
            "Invalid SDP format in body",
        ],
        "fix_generic": "Check SIP message for syntax errors. Enable SIP debug on sending device.",
        "fix_cube": 'Enable "debug ccsip messages" on CUBE to see the malformed message.',
    },
    401: {
        "name": "Unauthorized",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "AUTHENTICATION",
        "description": "Authentication credentials required",
        "common_causes": [
            "First 401 is normal (challenge-response flow)",
            "Second 401 with same nonce = wrong credentials",
            "Realm mismatch between client and server",
        ],
        "fix_generic": "Verify username/password in SIP device registration config.",
    },
    403: {
        "name": "Forbidden",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "HIGH",
        "failure_layer": "POLICY",
        "description": "Call blocked by policy (NOT authentication)",
        "common_causes": [
            "ACL/policy blocking the call",
            "Caller ID not in allowed list",
            "Toll restriction policy on CUCM",
            "SBC policy rejecting specific number format",
            "Number blocked by carrier",
            "STIR/SHAKEN attestation too low (C-level blocked)",
        ],
        "fix_cucm": "Check calling restrictions, CSS/Partition, toll restriction.",
        "fix_generic": "Check ACL on SBC, carrier policy, number format rules.",
    },
    404: {
        "name": "Not Found",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "HIGH",
        "failure_layer": "SIGNALING",
        "description": "Destination number/URI does not exist",
        "common_causes": [
            "Wrong number dialed",
            "Extension not provisioned in PBX",
            "Dial plan not matching (number not routed)",
            "SIP trunk sending to wrong domain",
            "DNS resolution failure for SIP URI domain",
        ],
        "fix_cucm": "Check Route Plan Report → search number → verify CSS.",
        "fix_generic": "Verify number exists in directory, check dial plan routing.",
    },
    405: {
        "name": "Method Not Allowed",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "SIGNALING",
        "description": "Server does not support the requested SIP method",
        "common_causes": ["Sending REFER to device that doesn't support transfer"],
    },
    407: {
        "name": "Proxy Authentication Required",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "AUTHENTICATION",
        "description": "Proxy requires authentication (same as 401 but from proxy)",
    },
    408: {
        "name": "Request Timeout",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "HIGH",
        "failure_layer": "NETWORK",
        "description": "No response received within SIP timer timeout",
        "common_causes": [
            "Destination device unreachable (network, firewall)",
            "SIP server overloaded (high CPU/memory)",
            "DNS resolution timeout",
            "NAT traversal failure",
            "Timer B expired (32 seconds default)",
        ],
        "fix_generic": "Check network path, firewall rules, device health.",
    },
    415: {
        "name": "Unsupported Media Type",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "MEDIA",
        "description": "Content-Type in body not supported",
    },
    420: {
        "name": "Bad Extension",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "SIGNALING",
        "description": "Require header lists unsupported option-tag",
    },
    480: {
        "name": "Temporarily Unavailable",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "SIGNALING",
        "description": "Callee temporarily unavailable",
        "common_causes": [
            "Phone in DND mode",
            "No registered devices for this extension",
            "All lines busy",
            "SIP registration expired",
        ],
        "fix_generic": "Check device registration status, DND setting.",
    },
    481: {
        "name": "Call/Transaction Does Not Exist",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "HIGH",
        "failure_layer": "SIGNALING",
        "description": "SIP dialog not found on server",
        "common_causes": [
            "BYE sent for call that already ended",
            "ACK for call that timed out",
            "CUCM/SBC failover — new node doesn't know about the call",
            "Mid-call device restart",
        ],
        "fix_generic": "Check device stability, failover configuration.",
    },
    482: {
        "name": "Loop Detected",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "HIGH",
        "failure_layer": "SIGNALING",
        "description": "Routing loop detected (Max-Forwards or Via loop)",
        "fix_generic": "Check dial plans on all devices for routing loops.",
    },
    483: {
        "name": "Too Many Hops",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "HIGH",
        "failure_layer": "SIGNALING",
        "description": "Max-Forwards header reached 0",
        "fix_generic": "Check for routing loops, reduce proxy chain length.",
    },
    484: {
        "name": "Address Incomplete",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "SIGNALING",
        "description": "Dialed number is incomplete (en-bloc dialing issue)",
    },
    486: {
        "name": "Busy Here",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "LOW",
        "failure_layer": "SIGNALING",
        "description": "Endpoint busy — user is on another call",
    },
    487: {
        "name": "Request Terminated",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "LOW",
        "failure_layer": "SIGNALING",
        "description": "INVITE cancelled before answered (normal response to CANCEL)",
        "common_causes": [
            "User hung up before call connected (normal)",
            "Dial timeout configured too short",
            "Hunting group next-agent timeout",
        ],
    },
    488: {
        "name": "Not Acceptable Here",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "HIGH",
        "failure_layer": "MEDIA",
        "description": "Media negotiation failed — codec/SDP mismatch",
        "common_causes": [
            "No common codec between offer and answer",
            "SRTP vs RTP mismatch",
            "DTMF method mismatch (rare alone)",
            "Media direction conflict",
            "Missing required codec for carrier (e.g. G.711 mandatory)",
        ],
        "fix_cube": (
            "voice class codec X\n"
            " codec preference 1 g711ulaw\n"
            " codec preference 2 g729r8"
        ),
        "fix_cucm": "Region Matrix — expand codec list between regions.",
        "fix_audiocodes": "Voice Profile → Coders — add missing codec.",
    },
    489: {
        "name": "Bad Event",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "SIGNALING",
        "description": "SUBSCRIBE event type not supported",
    },
    491: {
        "name": "Request Pending",
        "class": "CLIENT_ERROR",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "SIGNALING",
        "description": "Overlapping INVITE (re-INVITE collision / glare)",
    },

    # 5xx Server Errors
    500: {
        "name": "Server Internal Error",
        "class": "SERVER_ERROR",
        "is_error": True,
        "severity": "CRITICAL",
        "failure_layer": "SIGNALING",
        "description": "Server-side bug or crash",
        "common_causes": [
            "CUCM database error or high load",
            "SBC memory/CPU exhaustion",
            "Software bug triggered by this call",
            "Transcoder/MTP resource unavailable",
        ],
        "fix_cucm": "Check CUCM Event Viewer for exceptions.",
        "fix_generic": "Check server logs, restart service if persistent.",
    },
    502: {
        "name": "Bad Gateway",
        "class": "SERVER_ERROR",
        "is_error": True,
        "severity": "HIGH",
        "failure_layer": "SIGNALING",
        "description": "Upstream server returned invalid response",
        "fix_generic": "Check carrier SIP trunk configuration.",
    },
    503: {
        "name": "Service Unavailable",
        "class": "SERVER_ERROR",
        "is_error": True,
        "severity": "CRITICAL",
        "failure_layer": "CAPACITY",
        "description": "Server temporarily unable to process requests",
        "common_causes": [
            "SIP trunk capacity exhausted (all channels in use)",
            "Carrier outage",
            "SBC overloaded (CPU > 90%)",
            "CallManager service not running",
            "SBC license limit reached",
        ],
        "timing_analysis": "503 within <50ms = carrier immediate reject; 503 after >2s = timeout/overload",
        "fix_generic": "Check capacity, carrier status, license count.",
    },
    504: {
        "name": "Server Timeout",
        "class": "SERVER_ERROR",
        "is_error": True,
        "severity": "HIGH",
        "failure_layer": "NETWORK",
        "description": "Server waited too long for upstream response",
        "fix_generic": "Check network path to carrier, SIP timer configuration.",
    },
    513: {
        "name": "Message Too Large",
        "class": "SERVER_ERROR",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "SIGNALING",
        "description": "SIP message exceeds server capacity",
    },

    # 6xx Global Failures
    600: {
        "name": "Busy Everywhere",
        "class": "GLOBAL_FAILURE",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "SIGNALING",
        "description": "All endpoints for this user are busy",
    },
    603: {
        "name": "Decline",
        "class": "GLOBAL_FAILURE",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "SIGNALING",
        "description": "User explicitly rejected the call",
    },
    604: {
        "name": "Does Not Exist Anywhere",
        "class": "GLOBAL_FAILURE",
        "is_error": True,
        "severity": "HIGH",
        "failure_layer": "SIGNALING",
        "description": "Number definitively does not exist (more definitive than 404)",
    },
    607: {
        "name": "Unwanted",
        "class": "GLOBAL_FAILURE",
        "is_error": True,
        "severity": "MEDIUM",
        "failure_layer": "POLICY",
        "description": "Caller identified as unwanted/blocked (RFC 8197 spam filter)",
    },
}


# ─── ISDN/Q.850 Disconnect Cause Codes (CUCM) ───────────────────

ISDN_CAUSE_CODES: Dict[int, Tuple[str, str]] = {
    0:   ("Normal call clearing", "Not an error — normal disconnect."),
    1:   ("Unallocated number", "Check partition/CSS in CUCM."),
    16:  ("Normal disconnect", "User hung up — not an error."),
    17:  ("User busy", "Check hunt group config."),
    18:  ("No user responding", "Check ring timeout settings."),
    21:  ("Call rejected", "Check class of service restrictions."),
    28:  ("Invalid number format", "Check dial plan / number transformations."),
    31:  ("Normal unspecified", "Usually harmless — normal variant."),
    34:  ("No circuit available", "Trunk capacity exhausted — add channels."),
    38:  ("Network out of order", "Carrier-side issue — contact carrier NOC."),
    41:  ("Temporary failure", "Transient — retry the call."),
    42:  ("Congestion", "Overloaded switch — check call volume."),
    47:  ("Resource unavailable", "MTP/transcoder exhausted in CUCM."),
    50:  ("Facility not subscribed", "Feature not licensed."),
    63:  ("Service unavailable", "General unavailability."),
    65:  ("Bearer capability not implemented", "Codec/media not supported."),
    88:  ("Incompatible destination", "Maps to SIP 488 — codec mismatch."),
    102: ("Timer recovery", "Usually T310 timer — check SIP timers."),
    111: ("Interworking error", "Protocol mismatch between networks."),
    127: ("Interworking unspecified", "Generic interworking issue."),
}


# ─── SIP Compact Header Forms ────────────────────────────────────

COMPACT_HEADERS: Dict[str, str] = {
    "v": "via",
    "f": "from",
    "t": "to",
    "m": "contact",
    "i": "call-id",
    "e": "content-encoding",
    "l": "content-length",
    "c": "content-type",
    "s": "subject",
    "k": "supported",
    "o": "event",
}


# ─── Platform Detection ─────────────────────────────────────────

PLATFORM_SIGNATURES: Dict[str, List[str]] = {
    "CISCO_CUCM": [
        "CiscoSystemsSIP-GW-UserAgent",
        "CCM|",
        "Cisco-CUCM",
        "ccsip",
    ],
    "CISCO_CUBE": [
        "Cisco-CUBE",
        "Cisco-SIPGateway",
        "ccsipDisplayMsg",
        "dial-peer voice",
    ],
    "AUDIOCODES": [
        "AudioCodes",
        "[S=", "[Tid=",
        "AUDIOCODES",
    ],
    "RIBBON_SBC": [
        "Ribbon",
        "GENBAND",
        "| SIPMSG |",
    ],
    "MICROSOFT_TEAMS": [
        "Microsoft",
        "Teams",
        "52.114.",
        "52.112.",
        "sip.pstnhub.microsoft.com",
    ],
    "ASTERISK": [
        "Asterisk",
        "res_pjsip",
        "chan_sip",
        "VERBOSE[",
    ],
    "FREESWITCH": [
        "FreeSWITCH",
        "sofia.c",
        "mod_sofia",
    ],
    "KAMAILIO": [
        "kamailio",
        "opensips",
        "Kamailio",
    ],
}


# ─── Carrier Codec Requirements ──────────────────────────────────

CARRIER_REQUIREMENTS: Dict[str, Dict] = {
    "AT&T": {
        "required_codecs": ["PCMU"],
        "supported_codecs": ["PCMU", "G729"],
        "dtmf": "RFC2833",
        "stir_shaken": "A-level for enterprise",
    },
    "Lumen/CenturyLink": {
        "required_codecs": ["PCMU"],
        "supported_codecs": ["PCMU"],
        "dtmf": "RFC2833",
        "fax": "T.38 supported",
    },
    "Twilio": {
        "required_codecs": ["PCMU"],
        "supported_codecs": ["PCMU", "PCMA", "G722", "OPUS"],
        "dtmf": "RFC2833",
        "stir_shaken": "Required",
    },
    "Verizon": {
        "required_codecs": ["PCMU"],
        "supported_codecs": ["PCMU"],
        "dtmf": "RFC2833",
        "registration": "SIP REGISTER required for inbound",
    },
    "Teams_Direct_Routing": {
        "required_codecs": ["PCMU", "PCMA"],
        "supported_codecs": ["PCMU", "PCMA", "G722"],
        "dtmf": "RFC2833",
        "tls": "TLS 1.2 minimum on port 5061",
        "options_keepalive": "Every 60 seconds",
        "certificate": "Must be from trusted CA, SAN must match FQDN",
    },
}


# ─── SIP Timer Definitions ──────────────────────────────────────

SIP_TIMERS: Dict[str, Dict] = {
    "T1": {"default_ms": 500, "description": "RTT estimate / retransmission base timer (UDP)"},
    "T2": {"default_ms": 4000, "description": "Maximum retransmission interval"},
    "T4": {"default_ms": 5000, "description": "Maximum duration a message will remain in the network"},
    "Timer_A": {"default_ms": 500, "description": "INVITE retransmission interval (starts at T1)"},
    "Timer_B": {"default_ms": 32000, "description": "INVITE transaction timeout (64*T1)"},
    "Timer_D": {"default_ms": 32000, "description": "Wait time after ACK for INVITE retrans absorption (UDP)"},
    "Timer_F": {"default_ms": 32000, "description": "Non-INVITE transaction timeout (64*T1)"},
    "Timer_H": {"default_ms": 32000, "description": "INVITE final response retransmission wait"},
}


def detect_platform(raw_text: str, messages_raw: str = "") -> Optional[str]:
    """Detect the platform from log format signatures."""
    combined = raw_text + " " + messages_raw
    for platform, signatures in PLATFORM_SIGNATURES.items():
        for sig in signatures:
            if sig in combined:
                return platform
    return None


def get_response_knowledge(code: int) -> Optional[Dict]:
    """Get knowledge about a specific SIP response code."""
    return SIP_RESPONSE_KNOWLEDGE.get(code)


def get_carrier_info(text: str) -> Optional[Tuple[str, Dict]]:
    """Try to identify the carrier from SIP headers/domains."""
    text_lower = text.lower()
    carrier_hints = {
        "att": "AT&T", "at&t": "AT&T",
        "lumen": "Lumen/CenturyLink", "centurylink": "Lumen/CenturyLink",
        "twilio": "Twilio",
        "verizon": "Verizon",
        "pstnhub.microsoft.com": "Teams_Direct_Routing",
        "teams": "Teams_Direct_Routing",
    }
    for hint, carrier in carrier_hints.items():
        if hint in text_lower:
            return carrier, CARRIER_REQUIREMENTS.get(carrier, {})
    return None


def get_isdn_cause(code: int) -> Optional[Tuple[str, str]]:
    """Get ISDN/Q.850 disconnect cause description."""
    return ISDN_CAUSE_CODES.get(code)
