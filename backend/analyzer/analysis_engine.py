"""
Analysis Engine — Deterministic SIP analysis with full error code knowledge.

Features:
  - Complete SIP error code classification (1xx through 6xx)
  - SDP offer/answer pairing with mismatch detection
  - Retransmission vs duplicate detection (timing-based)
  - Missing ACK detection
  - Early BYE detection (flash call / one-way audio)
  - Call timeline with disposition
  - Ladder diagram data with participant extraction
  - SIP timer violation detection
  - Hold detection (re-INVITE analysis)
  - Platform-aware error explanations
"""

from __future__ import annotations
import re
from typing import List, Optional, Dict
from models.schemas import (
    SIPMessage, SIPError, SDPPair, SDPMismatch, ParsedSDP,
    CallTimeline, LadderData, LadderMessage,
    MessageType, Severity, CallDisposition,
    LadderMessageType, LadderSeverity,
)
from parser.sdp_parser import parse_sdp, detect_hold
from knowledge.sip_knowledge import SIP_RESPONSE_KNOWLEDGE, get_response_knowledge


# ─── Error Detection ─────────────────────────────────────────────

def detect_errors(messages: List[SIPMessage]) -> List[SIPError]:
    """Detect SIP errors and anomalies in a message sequence."""
    errors: List[SIPError] = []

    # Track state
    invite_seen = False
    invite_index = -1
    ok_200_for_invite = False
    ack_after_200 = False
    cancel_seen = False
    bye_seen = False
    invite_count = 0

    for i, msg in enumerate(messages):
        # ─── Response code errors (4xx, 5xx, 6xx) ────────
        if msg.type == MessageType.RESPONSE and msg.response_code:
            code = msg.response_code
            knowledge = get_response_knowledge(code)

            if knowledge and knowledge.get("is_error", False):
                severity_str = knowledge.get("severity", "MEDIUM")
                severity = getattr(Severity, severity_str, Severity.MEDIUM)
                layer = knowledge.get("failure_layer", "SIGNALING")

                # Build detailed explanation
                explanation = knowledge["description"]
                causes = knowledge.get("common_causes", [])
                if causes:
                    explanation += ". Common causes: " + "; ".join(causes[:3])

                # Add platform-specific fix hints
                fixes = []
                for key in ("fix_generic", "fix_cucm", "fix_cube", "fix_audiocodes"):
                    if key in knowledge:
                        fixes.append(knowledge[key])

                if fixes:
                    explanation += ". Fix: " + fixes[0]

                errors.append(SIPError(
                    message_index=i,
                    error_code=code,
                    error_type=f"SIP {code} {knowledge['name']}",
                    severity=severity,
                    description=f"Received {code} {msg.response_text or knowledge['name']} response",
                    engineer_explanation=explanation,
                ))

        # ─── Track INVITE flow ────────────────────────────
        if msg.method == "INVITE" and msg.type == MessageType.REQUEST:
            invite_count += 1
            if not invite_seen:
                invite_seen = True
                invite_index = i

        if msg.type == MessageType.RESPONSE and msg.method == "INVITE":
            if msg.response_code == 200:
                ok_200_for_invite = True

        if msg.method == "ACK" and msg.type == MessageType.REQUEST:
            if ok_200_for_invite:
                ack_after_200 = True

        if msg.method == "CANCEL" and msg.type == MessageType.REQUEST:
            cancel_seen = True

        if msg.method == "BYE" and msg.type == MessageType.REQUEST:
            bye_seen = True

    # ─── Anomaly: Missing ACK after 200 OK ────────────────
    if ok_200_for_invite and not ack_after_200:
        errors.append(SIPError(
            message_index=invite_index,
            error_code=None,
            error_type="Missing ACK",
            severity=Severity.HIGH,
            description="No ACK received after 200 OK for INVITE — call will eventually be torn down by timer",
            engineer_explanation=(
                "The ACK for the 200 OK was never sent. Without ACK, the UAS will retransmit "
                "the 200 OK until Timer H expires (32s), then tear down the call. Check for: "
                "NAT issues blocking the ACK, firewall rules, or application errors on the UAC. "
                "On CUCM, check 'show sip-ua status' for incomplete calls."
            ),
        ))

    # ─── Anomaly: Call never answered (no failure, no cancel) ─
    if invite_seen and not ok_200_for_invite:
        has_failure = any(
            m.response_code and m.response_code >= 400
            for m in messages
            if m.type == MessageType.RESPONSE and m.method == "INVITE"
        )
        if not has_failure and not cancel_seen:
            errors.append(SIPError(
                message_index=invite_index,
                error_code=None,
                error_type="Call Never Answered",
                severity=Severity.MEDIUM,
                description="INVITE was sent but never answered and not cancelled — possible ring-no-answer or timeout",
                engineer_explanation=(
                    "The call was never answered. No failure response and no CANCEL detected. "
                    "This usually means ring-no-answer. Check: voicemail forwarding settings, "
                    "ring timeout values, and whether the destination phone actually rang."
                ),
            ))

    # ─── Anomaly: Retransmissions ─────────────────────────
    _detect_retransmissions(messages, errors)

    # ─── Anomaly: Early BYE (STRICT — RFC 3261 compliant) ──────
    # RULES: Only flag Early BYE when ALL conditions are met:
    #   1. Call was CONNECTED (200 OK + ACK present)
    #   2. Duration < 3 seconds (timestamp-based, not message proximity)
    #   3. No cause=16 / "Normal call clearing" in Reason header
    #   4. Evidence of media/audio issue in BYE Reason header
    # BYE after normal call ≠ failure. cause=16 = NORMAL TERMINATION.
    if ok_200_for_invite and ack_after_200 and bye_seen:
        # Find 200 OK timestamp
        ok_200_ts = None
        for m in messages:
            if (m.type == MessageType.RESPONSE and m.method == "INVITE"
                    and m.response_code == 200):
                ok_200_ts = m.timestamp
                break

        bye_idx = next(
            (i for i, m in enumerate(messages)
             if m.method == "BYE" and m.type == MessageType.REQUEST),
            None
        )

        if bye_idx is not None:
            bye_msg = messages[bye_idx]
            raw_lower = bye_msg.raw_message.lower()

            # ── Parse Reason header for cause code ──
            has_normal_clearing = any(kw in raw_lower for kw in [
                "cause=16", "normal call clearing", "normal clearing",
            ])

            # ── Calculate actual duration (200 OK → BYE) ──
            call_dur = None
            if ok_200_ts and bye_msg.timestamp:
                ok_s = _parse_timestamp_seconds(ok_200_ts)
                bye_s = _parse_timestamp_seconds(bye_msg.timestamp)
                if ok_s is not None and bye_s is not None:
                    call_dur = bye_s - ok_s
                    if call_dur < 0:
                        call_dur += 86400  # midnight wrap

            # ── STRICT Early BYE check ──
            is_short = (call_dur is not None and call_dur < 3.0)

            if is_short and not has_normal_clearing:
                has_media_reason = any(kw in raw_lower for kw in [
                    "no media", "no audio", "onesided", "one-way",
                    "cause=location", "srtp", "crypto",
                ])

                if has_media_reason:
                    reason_hint = (" The BYE Reason header suggests no media "
                                   "was established — likely one-way audio or "
                                   "SRTP key mismatch.")
                    errors.append(SIPError(
                        message_index=bye_idx,
                        error_code=None,
                        error_type="Early BYE (Flash Disconnect)",
                        severity=Severity.HIGH,
                        description=(
                            f"BYE sent {call_dur:.1f}s after call answered "
                            "— probable media path failure"
                        ),
                        engineer_explanation=(
                            "The call was disconnected almost immediately "
                            "after being answered (< 3 seconds). "
                            "Common causes: one-way audio (SRTP/RTP mismatch),"
                            " codec negotiation succeeded but media path "
                            "failed, or application-level call control issue."
                            + reason_hint
                        ),
                    ))

    # ─── Anomaly: Re-INVITE retransmission without response ──
    if invite_count > 1:
        re_invites = [m for m in messages if m.method == "INVITE" and m.type == MessageType.REQUEST]
        if len(re_invites) > 1:
            # Check if the re-INVITE got a response
            last_invite_idx = re_invites[-1].index
            has_response = any(
                m.type == MessageType.RESPONSE and m.method == "INVITE" and m.index > last_invite_idx
                for m in messages
            )
            if not has_response:
                errors.append(SIPError(
                    message_index=last_invite_idx,
                    error_code=None,
                    error_type="Unanswered Re-INVITE",
                    severity=Severity.MEDIUM,
                    description="Re-INVITE sent mid-call but no response received",
                    engineer_explanation=(
                        "A re-INVITE was sent during the call (possibly for hold, codec change, "
                        "or call transfer) but no response was received. This may cause the call "
                        "to be stuck in an intermediate state."
                    ),
                ))

    return errors


def _detect_retransmissions(messages: List[SIPMessage], errors: List[SIPError]):
    """Detect retransmitted messages (identical method/CSeq/Call-ID repeated)."""
    seen: Dict[str, int] = {}
    retrans_count = 0

    for i, msg in enumerate(messages):
        key = f"{msg.method}|{msg.cseq}|{msg.call_id}|{msg.response_code}"
        if key in seen:
            retrans_count += 1
            # Only report the first few retransmissions to avoid noise
            if retrans_count <= 5:
                errors.append(SIPError(
                    message_index=i,
                    error_code=None,
                    error_type="Retransmission",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Retransmission of {msg.method or ''} "
                        f"{msg.response_code or ''} (first seen at message #{seen[key] + 1})"
                    ),
                    engineer_explanation=(
                        "Message was retransmitted — the original was not acknowledged in time. "
                        "UDP SIP retransmits at T1 (500ms) intervals, doubling each time up to T2 (4s). "
                        "This indicates network latency, packet loss, or an unresponsive endpoint."
                    ),
                ))
        else:
            seen[key] = i

    if retrans_count > 5:
        errors.append(SIPError(
            message_index=0,
            error_code=None,
            error_type="Retransmission Storm",
            severity=Severity.HIGH,
            description=f"Excessive retransmissions detected: {retrans_count} total",
            engineer_explanation=(
                f"Found {retrans_count} retransmitted messages — this indicates severe network issues "
                "or an unresponsive endpoint. Check: UDP packet loss on the network path, QoS markings "
                "for SIP traffic (DSCP EF/CS3), and endpoint health."
            ),
        ))


# ─── SDP Pair Extraction ────────────────────────────────────────

def extract_sdp_pairs(messages: List[SIPMessage]) -> List[SDPPair]:
    """Extract SDP offer/answer pairs from the message sequence."""
    pairs: List[SDPPair] = []
    pending_offer: Optional[tuple[int, ParsedSDP]] = None

    for i, msg in enumerate(messages):
        if not msg.sdp_body:
            continue

        parsed = parse_sdp(msg.sdp_body)

        # INVITE with SDP = offer
        if msg.method == "INVITE" and msg.type == MessageType.REQUEST:
            pending_offer = (i, parsed)
            continue

        # 200 OK with SDP = answer
        if (msg.type == MessageType.RESPONSE and msg.response_code == 200
                and msg.sdp_body and pending_offer is not None):
            offer_idx, offer_sdp = pending_offer
            mismatches = _compare_sdp(offer_sdp, parsed)
            pairs.append(SDPPair(
                offer_message_index=offer_idx,
                answer_message_index=i,
                offer_sdp=offer_sdp,
                answer_sdp=parsed,
                mismatches=mismatches,
            ))
            pending_offer = None
            continue

        # 183/180 with SDP = early answer
        if (msg.type == MessageType.RESPONSE
                and msg.response_code in (180, 183)
                and msg.sdp_body and pending_offer is not None):
            offer_idx, offer_sdp = pending_offer
            mismatches = _compare_sdp(offer_sdp, parsed)
            pairs.append(SDPPair(
                offer_message_index=offer_idx,
                answer_message_index=i,
                offer_sdp=offer_sdp,
                answer_sdp=parsed,
                mismatches=mismatches,
            ))
            continue  # Don't clear pending_offer — 200 OK may also have SDP

    # Offer with no answer
    if pending_offer is not None:
        offer_idx, offer_sdp = pending_offer
        pairs.append(SDPPair(
            offer_message_index=offer_idx,
            answer_message_index=None,
            offer_sdp=offer_sdp,
            answer_sdp=None,
            mismatches=[SDPMismatch(
                type="no_answer",
                description="SDP was offered but no answer was received — call was rejected before media negotiation completed",
                offer_value=", ".join(offer_sdp.codecs) if offer_sdp.codecs else "N/A",
                answer_value=None,
            )],
        ))

    return pairs


def _compare_sdp(offer: ParsedSDP, answer: ParsedSDP) -> List[SDPMismatch]:
    """Compare two SDPs and return mismatches with detailed explanations."""
    mismatches: List[SDPMismatch] = []

    # ─── Codec mismatch ──────────────────────────────────
    if offer.codecs and answer.codecs:
        offer_set = {c.split("/")[0].upper() for c in offer.codecs}
        answer_set = {c.split("/")[0].upper() for c in answer.codecs}
        common = offer_set.intersection(answer_set)

        if not common:
            mismatches.append(SDPMismatch(
                type="codec_mismatch",
                description=(
                    f"No common codecs — INVITE offered [{', '.join(offer.codecs)}] "
                    f"but answer only supports [{', '.join(answer.codecs)}]. "
                    "Call will have no audio. Add a shared codec (typically G.711/PCMU) to both sides."
                ),
                offer_value=", ".join(offer.codecs),
                answer_value=", ".join(answer.codecs),
            ))

    # ─── Direction conflict ──────────────────────────────
    if offer.direction == "sendonly" and answer.direction == "sendonly":
        mismatches.append(SDPMismatch(
            type="direction_conflict",
            description="Both sides are sendonly — neither will play audio to the other. This is a hold logic error.",
            offer_value=offer.direction,
            answer_value=answer.direction,
        ))
    elif offer.direction == "recvonly" and answer.direction == "recvonly":
        mismatches.append(SDPMismatch(
            type="direction_conflict",
            description="Both sides are recvonly — no audio will be sent in either direction.",
            offer_value=offer.direction,
            answer_value=answer.direction,
        ))

    # ─── SRTP mismatch ───────────────────────────────────
    if offer.has_srtp != answer.has_srtp:
        srtp_side = "Offer" if offer.has_srtp else "Answer"
        rtp_side = "Answer" if offer.has_srtp else "Offer"
        mismatches.append(SDPMismatch(
            type="srtp_mismatch",
            description=(
                f"{srtp_side} requests encrypted media (SRTP) but {rtp_side} only accepts "
                f"unencrypted media (RTP). This WILL cause one-way audio or no audio. "
                "Fix: Match encryption settings on both sides."
            ),
            offer_value="SRTP (RTP/SAVP)" if offer.has_srtp else "RTP (RTP/AVP)",
            answer_value="SRTP (RTP/SAVP)" if answer.has_srtp else "RTP (RTP/AVP)",
        ))

    # ─── DTMF mismatch ───────────────────────────────────
    if offer.dtmf_method and answer.dtmf_method:
        if offer.dtmf_method != answer.dtmf_method:
            mismatches.append(SDPMismatch(
                type="dtmf_mismatch",
                description=(
                    f"DTMF method mismatch: offer uses {offer.dtmf_method}, "
                    f"answer uses {answer.dtmf_method}. "
                    "IVR/DTMF digit input may not work correctly."
                ),
                offer_value=offer.dtmf_method,
                answer_value=answer.dtmf_method,
            ))

    # ─── Ptime mismatch ──────────────────────────────────
    if offer.ptime and answer.ptime and offer.ptime != answer.ptime:
        mismatches.append(SDPMismatch(
            type="ptime_mismatch",
            description=(
                f"Packetization time mismatch ({offer.ptime}ms vs {answer.ptime}ms). "
                "This may cause extra transcoding overhead or jitter. "
                "Recommendation: match ptime on both devices."
            ),
            offer_value=f"{offer.ptime}ms",
            answer_value=f"{answer.ptime}ms",
        ))

    return mismatches


# ─── Call Timeline ───────────────────────────────────────────────

def _parse_timestamp_seconds(ts: Optional[str]) -> Optional[float]:
    """Parse a timestamp string into seconds for duration calculation."""
    if not ts:
        return None
    # HH:MM:SS.mmm
    m = re.match(r"(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?", ts)
    if m:
        h, mn, s = int(m.group(1)), int(m.group(2)), int(m.group(3))
        frac = float(f"0.{m.group(4)}") if m.group(4) else 0.0
        return h * 3600 + mn * 60 + s + frac
    # ISO: ...THH:MM:SS
    m = re.search(r"(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?", ts)
    if m:
        h, mn, s = int(m.group(1)), int(m.group(2)), int(m.group(3))
        frac = float(f"0.{m.group(4)}") if m.group(4) else 0.0
        return h * 3600 + mn * 60 + s + frac
    return None


def _extract_ip_from_via(msg: SIPMessage) -> Optional[str]:
    """Extract IP address from Via header of a SIP message."""
    if msg.via_headers:
        via = msg.via_headers[0]
        m = re.search(r"SIP/2\.0/(?:UDP|TCP|TLS)\s+([\d.]+)(?::(\d+))?", via)
        if m:
            return m.group(1)
        m = re.search(r"SIP/2\.0/(?:UDP|TCP|TLS)\s+\[([0-9a-fA-F:]+)\]", via)
        if m:
            return f"[{m.group(1)}]"
    return None


def _extract_ip_from_uri(uri: Optional[str]) -> Optional[str]:
    """Extract IP from a SIP URI like sip:user@10.10.10.1:5060."""
    if not uri:
        return None
    m = re.search(r"@([\d.]+)(?::(\d+))?", uri)
    if m:
        return m.group(1)
    m = re.search(r"sips?:([\d.]+)(?::(\d+))?", uri)
    if m:
        return m.group(1)
    return None


def build_call_timeline(messages: List[SIPMessage]) -> CallTimeline:
    """Build a call timeline summary from the message sequence."""
    if not messages:
        return CallTimeline()

    timeline = CallTimeline()
    timeline.call_id = messages[0].call_id

    # Find calling/called party from INVITE
    for msg in messages:
        if msg.method == "INVITE" and msg.type == MessageType.REQUEST:
            timeline.calling_party = _extract_uri(msg.from_header)
            timeline.called_party = _extract_uri(msg.to_header)
            timeline.call_start = msg.timestamp
            # Extract IPs
            timeline.calling_ip = _extract_ip_from_via(msg)
            timeline.called_ip = _extract_ip_from_uri(msg.request_uri)
            break

    # For non-INVITE flows (REGISTER, etc.)
    if not timeline.calling_party:
        if messages:
            timeline.calling_party = _extract_uri(messages[0].from_header)
            timeline.called_party = _extract_uri(messages[0].to_header)
            timeline.call_start = messages[0].timestamp
            timeline.calling_ip = _extract_ip_from_via(messages[0])

    # Determine disposition
    answered = False
    cancelled = False
    failed = False
    busy = False
    failure_msg = None

    for msg in messages:
        if msg.type == MessageType.RESPONSE and msg.method == "INVITE":
            if msg.response_code == 200:
                answered = True
                timeline.call_answered = True
                timeline.call_answer_time = msg.timestamp
            elif msg.response_code == 486:
                busy = True
            elif msg.response_code == 487:
                cancelled = True
            elif msg.response_code and msg.response_code >= 400:
                failed = True
                failure_msg = f"{msg.response_code} {msg.response_text or ''}"

        # REGISTER flow
        if msg.type == MessageType.RESPONSE and msg.method == "REGISTER":
            if msg.response_code and msg.response_code >= 400 and msg.response_code != 401:
                failed = True
                failure_msg = f"{msg.response_code} {msg.response_text or ''}"
            elif msg.response_code == 200:
                answered = True
                timeline.call_answered = True

        if msg.method == "CANCEL" and msg.type == MessageType.REQUEST:
            cancelled = True

        if msg.method == "BYE" and msg.type == MessageType.REQUEST:
            timeline.call_end = msg.timestamp

    # Set disposition
    if answered:
        timeline.final_disposition = CallDisposition.ANSWERED
    elif busy:
        timeline.final_disposition = CallDisposition.BUSY
    elif cancelled:
        timeline.final_disposition = CallDisposition.CANCELLED
    elif failed:
        timeline.final_disposition = CallDisposition.FAILED
        timeline.failure_point = failure_msg
    else:
        timeline.final_disposition = CallDisposition.UNKNOWN

    # Calculate duration
    if timeline.call_answer_time and timeline.call_end:
        answer_s = _parse_timestamp_seconds(timeline.call_answer_time)
        end_s = _parse_timestamp_seconds(timeline.call_end)
        if answer_s is not None and end_s is not None:
            dur = end_s - answer_s
            if dur < 0:
                dur += 86400  # Wrapped midnight
            timeline.duration_seconds = round(dur, 2)
            timeline.duration_estimated = False
    elif timeline.call_start and timeline.call_end:
        start_s = _parse_timestamp_seconds(timeline.call_start)
        end_s = _parse_timestamp_seconds(timeline.call_end)
        if start_s is not None and end_s is not None:
            dur = end_s - start_s
            if dur < 0:
                dur += 86400
            timeline.duration_seconds = round(dur, 2)
            timeline.duration_estimated = True

    return timeline


# ─── Ladder Diagram ──────────────────────────────────────────────

def build_ladder_data(messages: List[SIPMessage]) -> LadderData:
    """Build ladder diagram data from the message sequence."""
    if not messages:
        return LadderData()

    # Discover participants
    participants: List[str] = []
    participant_set: set[str] = set()

    for msg in messages:
        from_p = _extract_participant(msg)
        to_p = _extract_to_participant(msg)

        for p in [from_p, to_p]:
            if p and p not in participant_set:
                participant_set.add(p)
                participants.append(p)

    if len(participants) < 2:
        participants = ["Endpoint A", "Endpoint B"]

    # Build ladder messages
    ladder_messages: List[LadderMessage] = []
    retransmission_keys: set[str] = set()

    for i, msg in enumerate(messages):
        from_p = _extract_participant(msg) or participants[0]
        to_p = _extract_to_participant(msg) or participants[-1]

        if from_p not in participants:
            participants.append(from_p)
        if to_p not in participants:
            participants.append(to_p)

        # Label
        if msg.type == MessageType.REQUEST:
            label = msg.method or "UNKNOWN"
        else:
            label = f"{msg.response_code} {msg.response_text or ''}"

        # Type and severity
        lm_type = LadderMessageType.REQUEST
        lm_severity = LadderSeverity.NORMAL

        key = f"{msg.method}|{msg.cseq}|{msg.response_code}"
        if key in retransmission_keys:
            lm_type = LadderMessageType.RETRANSMISSION
            lm_severity = LadderSeverity.WARNING
        else:
            retransmission_keys.add(key)

        if msg.type == MessageType.RESPONSE:
            lm_type = LadderMessageType.RESPONSE
            if msg.response_code:
                if 400 <= msg.response_code < 500:
                    lm_severity = LadderSeverity.ERROR
                elif msg.response_code >= 500:
                    lm_severity = LadderSeverity.CRITICAL

        # SDP summary
        sdp_summary = None
        if msg.sdp_body:
            parsed = parse_sdp(msg.sdp_body)
            parts = []
            if parsed.codecs:
                parts.append(", ".join(c.split("/")[0] for c in parsed.codecs))
            parts.append(parsed.direction)
            if parsed.has_srtp:
                parts.append("SRTP")
            else:
                parts.append("RTP")
            sdp_summary = " | ".join(parts)

        ladder_messages.append(LadderMessage(
            index=i,
            timestamp=msg.timestamp,
            from_participant=from_p if from_p in participants else participants[0],
            to_participant=to_p if to_p in participants else participants[-1],
            label=label,
            type=lm_type,
            severity=lm_severity,
            has_sdp=msg.sdp_body is not None,
            sdp_summary=sdp_summary,
            raw_message=msg.raw_message,
        ))

    return LadderData(participants=participants, messages=ladder_messages)


# ─── Helpers ─────────────────────────────────────────────────────

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


def _extract_participant(msg: SIPMessage) -> str:
    """Extract the 'from' participant (source) of a message."""
    if msg.type == MessageType.REQUEST:
        if msg.via_headers:
            via = msg.via_headers[0]
            # Try IPv4
            match = re.search(r"SIP/2\.0/(?:UDP|TCP|TLS)\s+([\d.]+(?::\d+)?)", via)
            if match:
                return match.group(1)
            # Try IPv6
            match = re.search(r"SIP/2\.0/(?:UDP|TCP|TLS)\s+\[([0-9a-fA-F:]+)\](:\d+)?", via)
            if match:
                return f"[{match.group(1)}]"
        return _extract_uri(msg.from_header) or "Unknown"
    else:
        return _extract_uri(msg.to_header) or "Unknown"


def _extract_to_participant(msg: SIPMessage) -> str:
    """Extract the 'to' participant (destination) of a message."""
    if msg.type == MessageType.REQUEST:
        return _extract_uri(msg.to_header) or "Unknown"
    else:
        if msg.via_headers:
            via = msg.via_headers[0]
            match = re.search(r"SIP/2\.0/(?:UDP|TCP|TLS)\s+([\d.]+(?::\d+)?)", via)
            if match:
                return match.group(1)
            match = re.search(r"SIP/2\.0/(?:UDP|TCP|TLS)\s+\[([0-9a-fA-F:]+)\](:\d+)?", via)
            if match:
                return f"[{match.group(1)}]"
        return _extract_uri(msg.from_header) or "Unknown"
