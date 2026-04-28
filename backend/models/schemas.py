"""
Pydantic models for SIP Sherlock API schemas.
All data structures used across the application.
"""

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from enum import Enum


# ─── Enums ────────────────────────────────────────────────────────

class MessageDirection(str, Enum):
    SENT = "SENT"
    RECEIVED = "RECEIVED"
    UNKNOWN = "UNKNOWN"


class MessageType(str, Enum):
    REQUEST = "REQUEST"
    RESPONSE = "RESPONSE"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CallDisposition(str, Enum):
    ANSWERED = "ANSWERED"
    FAILED = "FAILED"
    BUSY = "BUSY"
    CANCELLED = "CANCELLED"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_FOUND = "NOT_FOUND"
    REJECTED = "REJECTED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    UNKNOWN = "UNKNOWN"


class FailureLayer(str, Enum):
    SIGNALING = "SIGNALING"
    MEDIA = "MEDIA"
    NETWORK = "NETWORK"
    AUTHENTICATION = "AUTHENTICATION"
    POLICY = "POLICY"
    CAPACITY = "CAPACITY"


class LadderMessageType(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    RETRANSMISSION = "retransmission"


class LadderSeverity(str, Enum):
    NORMAL = "normal"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# ─── SIP Message ──────────────────────────────────────────────────

class SIPMessage(BaseModel):
    """A single parsed SIP message."""
    index: int = 0
    timestamp: Optional[str] = None
    direction: MessageDirection = MessageDirection.UNKNOWN
    type: MessageType = MessageType.REQUEST
    method: Optional[str] = None
    request_uri: Optional[str] = None
    response_code: Optional[int] = None
    response_text: Optional[str] = None
    from_header: str = ""
    to_header: str = ""
    call_id: str = ""
    cseq: str = ""
    cseq_method: Optional[str] = None
    via_headers: List[str] = Field(default_factory=list)
    contact: Optional[str] = None
    user_agent: Optional[str] = None
    sdp_body: Optional[str] = None
    raw_message: str = ""


# ─── SDP Models ───────────────────────────────────────────────────

class ParsedSDP(BaseModel):
    """Parsed SDP body."""
    codecs: List[str] = Field(default_factory=list)
    codec_details: List[dict] = Field(default_factory=list)
    direction: str = "sendrecv"
    connection_ip: str = ""
    media_port: int = 0
    media_protocol: Optional[str] = None
    has_srtp: bool = False
    crypto_lines: List[str] = Field(default_factory=list)
    dtmf_payload_type: Optional[int] = None
    dtmf_method: Optional[str] = None
    ptime: Optional[int] = None
    bandwidth: Optional[str] = None
    is_fax: bool = False
    is_on_hold: bool = False
    hold_method: Optional[str] = None
    raw_sdp: Optional[str] = None


class SDPMismatch(BaseModel):
    """A single SDP mismatch between offer and answer."""
    type: str
    severity: str = "HIGH"
    field: str = ""
    description: str = ""
    offer_value: Optional[str] = None
    answer_value: Optional[str] = None
    explanation: str = ""


class SDPPair(BaseModel):
    """An SDP offer/answer pair."""
    offer_message_index: int
    answer_message_index: Optional[int] = None
    offer_sdp: Optional[ParsedSDP] = None
    answer_sdp: Optional[ParsedSDP] = None
    mismatches: List[SDPMismatch] = Field(default_factory=list)


# ─── Error Detection ─────────────────────────────────────────────

class SIPError(BaseModel):
    """A detected SIP error or anomaly."""
    message_index: int
    error_code: Optional[int] = None
    error_type: str
    severity: Severity
    description: str
    engineer_explanation: str


# ─── Call Timeline ────────────────────────────────────────────────

class CallTimeline(BaseModel):
    """Timeline summary of a SIP call."""
    call_id: str = ""
    calling_party: Optional[str] = None
    calling_ip: Optional[str] = None
    called_party: Optional[str] = None
    called_ip: Optional[str] = None
    call_start: Optional[str] = None
    call_answered: bool = False
    call_answer_time: Optional[str] = None
    call_end: Optional[str] = None
    duration_seconds: Optional[float] = None
    duration_estimated: bool = False
    final_disposition: CallDisposition = CallDisposition.UNKNOWN
    failure_point: Optional[str] = None


# ─── Ladder Diagram ──────────────────────────────────────────────

class LadderMessage(BaseModel):
    """A single message in the ladder diagram."""
    index: int
    timestamp: Optional[str] = None
    from_participant: str
    to_participant: str
    label: str
    type: LadderMessageType = LadderMessageType.REQUEST
    severity: LadderSeverity = LadderSeverity.NORMAL
    has_sdp: bool = False
    sdp_summary: Optional[str] = None
    raw_message: str = ""


class LadderData(BaseModel):
    """Data for rendering a SIP ladder diagram."""
    participants: List[str] = Field(default_factory=list)
    participant_labels: Dict[str, str] = Field(default_factory=dict)
    messages: List[LadderMessage] = Field(default_factory=list)


# ─── RCA (Root Cause Analysis) ───────────────────────────────────

class FixItem(BaseModel):
    """A recommended fix action."""
    priority: int = 1
    action: str = ""
    detail: str = ""
    platform: str = "Generic"


class RCAResult(BaseModel):
    """Root Cause Analysis result."""
    root_cause: str = ""
    root_cause_detail: str = ""
    failure_layer: str = "SIGNALING"
    failure_location: str = ""
    confidence: int = 0
    contributing_factors: List[str] = Field(default_factory=list)
    recommended_fixes: List[FixItem] = Field(default_factory=list)
    config_snippet: Optional[str] = None
    escalation_needed: bool = False
    escalation_reason: Optional[str] = None


# ─── Full Analysis Result ────────────────────────────────────────

class AnalysisResult(BaseModel):
    """Complete analysis result returned by all analyze endpoints."""
    analysis_id: str
    input_type: str  # "text" | "pcap" | "log"
    parsed_message_count: int = 0
    call_timeline: CallTimeline = Field(default_factory=CallTimeline)
    ladder_data: LadderData = Field(default_factory=LadderData)
    detected_errors: List[SIPError] = Field(default_factory=list)
    sdp_pairs: List[SDPPair] = Field(default_factory=list)
    rca: RCAResult = Field(default_factory=RCAResult)
    detected_platform: str = "GENERIC"
    processing_time_ms: int = 0
    analyzed_at: str = ""


# ─── Request Models ──────────────────────────────────────────────

class TextAnalysisRequest(BaseModel):
    """Request body for text-based SIP analysis."""
    sip_text: str
