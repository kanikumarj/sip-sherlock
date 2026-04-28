"""
RCA Engine — AI-powered Root Cause Analysis with precision prompts.
Falls back to enhanced deterministic rule-based analysis if API is unavailable.
"""

from __future__ import annotations
import os
import json
import logging
from typing import List, Optional
from models.schemas import (
    SIPMessage, SIPError, SDPPair, CallTimeline,
    RCAResult, FixItem, Severity, MessageType,
)
from knowledge.sip_knowledge import (
    detect_platform, get_response_knowledge, SIP_RESPONSE_KNOWLEDGE,
)

logger = logging.getLogger(__name__)

# ─── Precision System Prompt ─────────────────────────────────────

SYSTEM_PROMPT = """You are SIP Sherlock — a SIP protocol expert with 25+ years of enterprise voice engineering experience.

PLATFORMS: Cisco CUCM, CUBE, Microsoft Teams Direct Routing, AudioCodes SBC, Ribbon SBC, Genesys Cloud CX, Asterisk, FreeSWITCH, Kamailio, and all major carrier SIP trunking.
PROTOCOLS: SIP (RFC 3261+), SDP (RFC 4566), RTP/RTCP, SRTP, STIR/SHAKEN.

RULES (FOLLOW STRICTLY):
1. EVIDENCE ONLY: Every conclusion MUST cite specific evidence from the data. If uncertain, state "Possible cause — insufficient data to confirm."
2. PLATFORM SPECIFICITY: If platform is detected, give platform-specific diagnosis and fix. Generic advice is unacceptable when platform is identifiable.
3. HONEST CONFIDENCE: 90-100=multiple evidence points; 70-89=primary evidence with minor gaps; 50-69=suggestive but not conclusive; 30-49=possible cause, insufficient data; 0-29=cannot determine.
4. FIX SPECIFICITY: Provide exact config steps, not vague advice.
5. NEVER HALLUCINATE: If information is not in the data, say so explicitly.
6. PRIORITIZE PRIMARY FAILURE: Identify root cause vs secondary effects (e.g., 503→CANCEL→487: 503 is primary).

Return ONLY valid JSON with this structure:
{
  "root_cause": "Single precise sentence",
  "root_cause_detail": "Technical explanation with evidence references",
  "failure_layer": "SIGNALING|MEDIA|NETWORK|AUTHENTICATION|POLICY|CAPACITY",
  "failure_location": "Which device/hop caused the failure",
  "confidence": 0-100,
  "contributing_factors": ["factor1", "factor2"],
  "recommended_fixes": [
    {"priority": 1, "action": "What to do", "detail": "Exact steps", "platform": "Platform name"}
  ],
  "config_snippet": "Exact config lines if applicable, else null",
  "escalation_needed": false,
  "escalation_reason": null
}"""


def _build_analysis_context(
    messages: List[SIPMessage],
    errors: List[SIPError],
    sdp_pairs: List[SDPPair],
    timeline: CallTimeline,
) -> dict:
    """Build structured context for Claude with full SDP and flow details."""
    # Detect platform
    raw_combined = " ".join(m.raw_message for m in messages[:5])
    platform = detect_platform(raw_combined)

    # Message flow with SDP details
    flow = []
    for msg in messages:
        entry = {"index": msg.index, "direction": msg.direction.value}
        if msg.method:
            entry["method"] = msg.method
        if msg.response_code:
            entry["response_code"] = msg.response_code
            entry["response_text"] = msg.response_text
        if msg.sdp_body:
            entry["has_sdp"] = True
        if msg.timestamp:
            entry["timestamp"] = msg.timestamp
        flow.append(entry)

    # Build flow narrative
    flow_narrative = []
    for msg in messages:
        arrow = "→" if msg.direction.value == "SENT" else "←" if msg.direction.value == "RECEIVED" else "·"
        if msg.type == MessageType.REQUEST:
            flow_narrative.append(f"{arrow} {msg.method}")
        else:
            flow_narrative.append(f"{arrow} {msg.response_code} {msg.response_text or ''}")

    # SDP analysis summary
    sdp_summary = {}
    for pair in sdp_pairs:
        sdp_summary = {
            "offer_codecs": pair.offer_sdp.codecs if pair.offer_sdp else [],
            "answer_codecs": pair.answer_sdp.codecs if pair.answer_sdp else None,
            "offer_srtp": pair.offer_sdp.has_srtp if pair.offer_sdp else False,
            "answer_srtp": pair.answer_sdp.has_srtp if pair.answer_sdp else None,
            "mismatches": [{"type": m.type, "description": m.description} for m in pair.mismatches],
        }
        break  # Primary pair only

    return {
        "detected_platform": platform,
        "call_summary": {
            "calling_party": timeline.calling_party,
            "called_party": timeline.called_party,
            "disposition": timeline.final_disposition.value,
            "failure_point": timeline.failure_point,
        },
        "sip_flow_sequence": flow_narrative,
        "message_flow": flow,
        "detected_errors": [
            {"type": e.error_type, "code": e.error_code, "severity": e.severity.value, "description": e.description}
            for e in errors
        ],
        "sdp_analysis": sdp_summary,
        "total_messages": len(messages),
    }


async def generate_rca(
    messages: List[SIPMessage],
    errors: List[SIPError],
    sdp_pairs: List[SDPPair],
    timeline: CallTimeline,
) -> RCAResult:
    """Generate RCA using Claude API, with deterministic fallback."""
    api_key = os.getenv("ANTHROPIC_API_KEY", "")

    if not api_key:
        logger.warning("ANTHROPIC_API_KEY not set — using deterministic fallback RCA")
        return _fallback_rca(messages, errors, sdp_pairs, timeline)

    context = _build_analysis_context(messages, errors, sdp_pairs, timeline)

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": f"Analyze this SIP call:\n\n{json.dumps(context, indent=2)}"
            }],
            timeout=30.0,
        )

        text = response.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0]
            text = text.strip()

        rca_data = json.loads(text)
        fixes = [FixItem(
            priority=f.get("priority", 1),
            action=f.get("action", ""),
            detail=f.get("detail", ""),
            platform=f.get("platform", "Generic"),
        ) for f in rca_data.get("recommended_fixes", [])]

        return RCAResult(
            root_cause=rca_data.get("root_cause", ""),
            root_cause_detail=rca_data.get("root_cause_detail", ""),
            failure_layer=rca_data.get("failure_layer", "SIGNALING"),
            failure_location=rca_data.get("failure_location", ""),
            confidence=rca_data.get("confidence", 0),
            contributing_factors=rca_data.get("contributing_factors", []),
            recommended_fixes=fixes,
            config_snippet=rca_data.get("config_snippet"),
            escalation_needed=rca_data.get("escalation_needed", False),
            escalation_reason=rca_data.get("escalation_reason"),
        )
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Claude RCA JSON: {e}")
        return _fallback_rca(messages, errors, sdp_pairs, timeline)
    except Exception as e:
        logger.error(f"Claude API call failed: {e}")
        return _fallback_rca(messages, errors, sdp_pairs, timeline)


# ─── Enhanced Deterministic Fallback ─────────────────────────────

def _fallback_rca(
    messages: List[SIPMessage],
    errors: List[SIPError],
    sdp_pairs: List[SDPPair],
    timeline: CallTimeline,
) -> RCAResult:
    """
    Deterministic RCA Engine — L3 SIP Analysis Pipeline.

    STRICT ORDER:
      Step 1: SIP Call Lifecycle
      Step 2: Signaling Validation
      Step 3: SDP / Media Negotiation
      Step 4: Call Duration Engine
      Step 5: BYE Analysis Engine
      Step 6: Early BYE Detection (STRICT)
      Step 7: Root Cause Classification
      Step 8: Confidence Engine

    CORE RULES:
      - 200 OK + ACK = CALL CONNECTED
      - BYE after ACK = NORMAL TERMINATION (NOT failure)
      - cause=16 = NORMAL CALL CLEARING
      - Short duration ≠ failure
    """
    import re

    # Detect platform
    raw_combined = " ".join(m.raw_message for m in messages[:5])
    platform = detect_platform(raw_combined) or "Unknown"

    # ══════════════════════════════════════════════════════════
    # STEP 1 — SIP CALL LIFECYCLE ENGINE
    # ══════════════════════════════════════════════════════════
    has_invite = any(m.method == "INVITE" and m.type == MessageType.REQUEST for m in messages)
    has_200_ok_invite = any(
        m.type == MessageType.RESPONSE and m.response_code == 200
        and (m.method == "INVITE" or (m.cseq_method == "INVITE"))
        for m in messages
    )
    has_ack = any(m.method == "ACK" and m.type == MessageType.REQUEST for m in messages)
    has_bye = any(m.method == "BYE" and m.type == MessageType.REQUEST for m in messages)
    has_cancel = any(m.method == "CANCEL" and m.type == MessageType.REQUEST for m in messages)

    call_connected = has_200_ok_invite and has_ack
    call_completed = call_connected and has_bye

    # 4xx/5xx/6xx error responses on INVITE
    invite_errors = [
        m for m in messages
        if m.type == MessageType.RESPONSE and m.response_code
        and m.response_code >= 400
        and (m.method == "INVITE" or m.cseq_method == "INVITE")
    ]
    call_failed = bool(invite_errors) and not call_connected

    # ══════════════════════════════════════════════════════════
    # STEP 3 — SDP / MEDIA NEGOTIATION
    # ══════════════════════════════════════════════════════════
    sdp_mismatches = []
    for pair in sdp_pairs:
        sdp_mismatches.extend(pair.mismatches)
    srtp_mm = [m for m in sdp_mismatches if m.type == "srtp_mismatch"]

    # ══════════════════════════════════════════════════════════
    # STEP 4 — CALL DURATION ENGINE
    # ══════════════════════════════════════════════════════════
    duration = timeline.duration_seconds
    duration_str = f"{duration:.1f}s" if duration is not None else "N/A (no timestamps)"

    # ══════════════════════════════════════════════════════════
    # STEP 5 — BYE ANALYSIS ENGINE
    # ══════════════════════════════════════════════════════════
    bye_sender = None
    bye_reason = None
    has_normal_clearing = False

    if has_bye:
        for m in messages:
            if m.method == "BYE" and m.type == MessageType.REQUEST:
                raw_lower = m.raw_message.lower()
                # Parse Reason header
                reason_match = re.search(r'reason:\s*(.+)', m.raw_message, re.IGNORECASE)
                if reason_match:
                    bye_reason = reason_match.group(1).strip()
                # Check cause=16 (Normal Call Clearing)
                if any(kw in raw_lower for kw in [
                    "cause=16", "normal call clearing", "normal clearing",
                ]):
                    has_normal_clearing = True
                # Determine sender from Via
                if m.via_headers:
                    via = m.via_headers[0]
                    ip_match = re.search(r'SIP/2\.0/(?:UDP|TCP|TLS)\s+([\d.]+)', via)
                    bye_sender = ip_match.group(1) if ip_match else "initiating endpoint"
                else:
                    bye_sender = "initiating endpoint"
                break

    # ══════════════════════════════════════════════════════════
    # STEP 6 — EARLY BYE DETECTION (STRICT)
    # ══════════════════════════════════════════════════════════
    # ALL conditions required: connected + duration<3s + no cause=16 + media evidence
    is_early_bye = False
    if call_connected and has_bye and not has_normal_clearing:
        if duration is not None and duration < 3.0:
            for m in messages:
                if m.method == "BYE" and m.type == MessageType.REQUEST:
                    raw_lower = m.raw_message.lower()
                    if any(kw in raw_lower for kw in [
                        "no media", "no audio", "onesided", "one-way",
                        "srtp", "crypto", "cause=location",
                    ]):
                        is_early_bye = True
                    break

    # ══════════════════════════════════════════════════════════
    # STEP 7 — ROOT CAUSE CLASSIFICATION
    # ══════════════════════════════════════════════════════════

    # ─── PATH A: CONNECTED CALL — Early BYE (media failure) ──
    if call_connected and is_early_bye:
        return RCAResult(
            root_cause="Early BYE — media path failure within 3 seconds of call establishment",
            root_cause_detail=(
                f"Call connected (200 OK + ACK) but BYE was sent after only {duration_str}. "
                "The Reason header indicates a media-layer failure (no audio / one-way audio). "
                "This is NOT a signaling failure — the call connected but the RTP media path failed."
            ),
            failure_layer="MEDIA",
            failure_location="RTP media path between endpoints",
            confidence=88,
            contributing_factors=[
                "SRTP/RTP encryption mismatch",
                "Firewall blocking RTP ports",
                "NAT traversal failure on media",
                "Codec negotiated but media IP unreachable",
            ],
            recommended_fixes=[
                FixItem(priority=1, action="Verify RTP/SRTP consistency", detail="Ensure both sides use RTP or both use SRTP. Check media security profiles.", platform="Generic"),
                FixItem(priority=2, action="Check firewall for RTP port range", detail="Ensure UDP ports 16384-32767 (default) are open bidirectionally.", platform="Generic"),
            ],
        )

    # ─── PATH B: CONNECTED CALL — SRTP mismatch ─────────────
    if call_connected and srtp_mm:
        return _rca_srtp_mismatch(srtp_mm[0], platform)

    # ─── PATH C: CONNECTED CALL — SUCCESSFUL ─────────────────
    if call_connected:
        quality_notes = []
        retrans = [e for e in errors if "Retransmission" in e.error_type]
        if retrans:
            quality_notes.append(f"{len(retrans)} retransmission(s) — check network QoS")

        # Build evidence-based detail
        bye_info = ""
        if bye_reason:
            bye_info = f" BYE Reason: {bye_reason}."
        elif has_normal_clearing:
            bye_info = " BYE with cause=16 (Normal Call Clearing)."
        elif has_bye:
            bye_info = f" BYE sent by {bye_sender or 'endpoint'} — normal termination."

        codec_info = ""
        for pair in sdp_pairs:
            if pair.offer_sdp and pair.answer_sdp:
                offer_c = ", ".join(pair.offer_sdp.codecs[:3])
                answer_c = ", ".join(pair.answer_sdp.codecs[:3])
                codec_info = f" Codecs: offered [{offer_c}], answered [{answer_c}] — match confirmed."
                break
            elif pair.offer_sdp:
                offer_c = ", ".join(pair.offer_sdp.codecs[:3])
                codec_info = f" Codecs offered: [{offer_c}]."
                break

        detail = (
            f"SIGNALING: INVITE → 200 OK → ACK confirms call CONNECTED. "
            f"MEDIA: SDP negotiation successful.{codec_info} "
            f"DURATION: {duration_str}.{bye_info}"
        )

        if quality_notes:
            detail += f" QUALITY NOTES: {'; '.join(quality_notes)}."

        return RCAResult(
            root_cause="Call completed successfully — no issues detected",
            root_cause_detail=detail,
            failure_layer="NONE",
            failure_location="N/A",
            confidence=96 if not quality_notes else 90,
            contributing_factors=quality_notes if quality_notes else [],
            recommended_fixes=[
                FixItem(priority=1, action="No action required",
                        detail="Call flow is normal. All SIP lifecycle stages completed correctly.",
                        platform="Generic")
            ] if not quality_notes else [
                FixItem(priority=1, action="Investigate network QoS",
                        detail="Check UDP packet loss and jitter on voice VLAN. Verify DSCP EF/CS3 markings.",
                        platform="Generic"),
            ],
        )

    # ─── PATH D: CANCELLED CALL (RFC 3261 §15) ────────────────
    # CANCEL + 487 is NORMAL SIP behavior. 487 "Request Terminated" is the
    # expected response when a CANCEL is processed. This MUST be checked
    # BEFORE error code routing to prevent 487 false positives.
    if has_cancel:
        # Check for real pre-CANCEL errors (e.g., 503 before CANCEL was sent)
        cancel_index = next(
            (i for i, m in enumerate(messages) if m.method == "CANCEL" and m.type == MessageType.REQUEST),
            len(messages)
        )
        pre_cancel_errors = [
            m for m in messages
            if m.type == MessageType.RESPONSE and m.response_code
            and m.response_code >= 400 and m.response_code != 487
            and m.index < cancel_index
            and (m.method == "INVITE" or m.cseq_method == "INVITE")
        ]
        if not pre_cancel_errors:
            # Pure CANCEL scenario — not a failure
            return RCAResult(
                root_cause="Call was cancelled before being answered",
                root_cause_detail=(
                    "CANCEL was sent before 200 OK — the caller hung up or the system "
                    "timed out before the call was answered. The resulting 487 Request "
                    "Terminated is the expected RFC 3261 response to a CANCEL. "
                    "This is normal user behavior, not a system failure."
                ),
                failure_layer="NONE",
                failure_location="N/A",
                confidence=95,
                contributing_factors=["User cancelled call", "Ring-no-answer timeout"],
                recommended_fixes=[FixItem(priority=1, action="No action required", detail="CANCEL is a normal SIP operation. Check if user intentionally hung up.", platform="Generic")],
            )

    # ─── PATH E: FAILED CALL — Error code routing ────────────
    # Find primary error (highest severity, prefer 4xx/5xx on INVITE)
    # Exclude 487 when CANCEL is present (already handled above)
    primary_error: Optional[SIPError] = None
    for err in sorted(errors, key=lambda e: _severity_rank(e.severity), reverse=True):
        if err.error_code and err.error_code >= 400:
            # Skip 487 if CANCEL was present (it fell through due to pre-cancel errors)
            if err.error_code == 487 and has_cancel:
                continue
            primary_error = err
            break
    if not primary_error:
        for err in sorted(errors, key=lambda e: _severity_rank(e.severity), reverse=True):
            if err.error_code:
                if err.error_code == 487 and has_cancel:
                    continue
                primary_error = err
                break

    # Route by specific error code
    if primary_error and primary_error.error_code == 488:
        return _rca_488(sdp_pairs, sdp_mismatches, platform, messages)
    if primary_error and primary_error.error_code == 503:
        return _rca_503(messages, platform)
    if primary_error and primary_error.error_code in (401, 403):
        return _rca_auth(primary_error, messages, platform)
    if primary_error and primary_error.error_code == 408:
        return _rca_408(platform)
    if primary_error and primary_error.error_code == 404:
        return _rca_404(platform)
    if primary_error and primary_error.error_code == 480:
        return _rca_480(messages, platform)
    if primary_error and primary_error.error_code == 482:
        return _rca_482(messages, platform)
    if primary_error and primary_error.error_code == 484:
        return _rca_484(messages, platform)
    if primary_error and primary_error.error_code == 486:
        return _rca_486(messages, platform)
    if primary_error and primary_error.error_code == 500:
        return _rca_500(messages, platform)

    # SRTP mismatch on non-connected call
    if srtp_mm:
        return _rca_srtp_mismatch(srtp_mm[0], platform)

    # Generic error with code (from SIP knowledge base)
    if primary_error and primary_error.error_code:
        knowledge = get_response_knowledge(primary_error.error_code)
        if knowledge:
            return RCAResult(
                root_cause=f"Call failed with {primary_error.error_code} {knowledge['name']}",
                root_cause_detail=knowledge["description"] + ". " + "; ".join(knowledge.get("common_causes", [])[:3]),
                failure_layer=knowledge.get("failure_layer", "SIGNALING"),
                failure_location="Remote SIP endpoint",
                confidence=70,
                contributing_factors=knowledge.get("common_causes", [])[:5],
                recommended_fixes=[FixItem(priority=1, action=knowledge.get("fix_generic", "Review SIP debug logs"), detail="Enable SIP debug on the failing device and capture a new trace.", platform="Generic")],
                escalation_needed=knowledge.get("severity") == "CRITICAL",
                escalation_reason="Critical severity error" if knowledge.get("severity") == "CRITICAL" else None,
            )

    # ─── PATH F: Non-4xx/5xx anomalies on FAILED calls ──────
    if errors and not call_connected:
        error_summary = ", ".join(e.error_type for e in errors[:3])
        return RCAResult(
            root_cause=f"Call anomalies detected: {error_summary}",
            root_cause_detail=f"Analysis detected {len(errors)} issue(s): {error_summary}. Call did not reach CONNECTED state.",
            failure_layer="SIGNALING", failure_location="SIP call flow", confidence=55,
            contributing_factors=[e.description for e in errors[:5]],
            recommended_fixes=[FixItem(priority=1, action="Review detected anomalies in ladder diagram", detail="Examine each error in the context of the full SIP message flow.", platform="Generic")],
        )

    # ─── PATH G: Insufficient data ───────────────────────────
    return RCAResult(
        root_cause="Insufficient SIP data to determine call outcome",
        root_cause_detail="The trace does not contain enough SIP messages to determine call state. The log may be incomplete or truncated. Capture a complete trace from INVITE to BYE/CANCEL.",
        failure_layer="SIGNALING", failure_location="Unknown", confidence=20,
        contributing_factors=["Incomplete SIP trace", "Missing messages"],
        recommended_fixes=[FixItem(priority=1, action="Capture complete SIP trace", detail="Re-capture from INVITE to BYE/CANCEL. On Cisco: 'debug ccsip messages'. On AudioCodes: enable Syslog.", platform="Generic")],
    )


def _rca_488(sdp_pairs, sdp_mismatches, platform, messages) -> RCAResult:
    """Precise RCA for 488 Not Acceptable Here."""
    # Extract codec info from SDP
    offer_codecs = []
    for pair in sdp_pairs:
        if pair.offer_sdp:
            offer_codecs = pair.offer_sdp.codecs
            break

    codec_str = ", ".join(offer_codecs) if offer_codecs else "unknown codecs"

    detail = (
        f"The INVITE offered [{codec_str}] but the remote endpoint could not accept any of them. "
        "The remote side rejected with 488 Not Acceptable Here."
    )

    fixes = []
    if "CUBE" in platform or "CISCO" in platform:
        fixes.append(FixItem(priority=1, action="Add G.711 as primary codec on CUBE dial-peer",
            detail="dial-peer voice X voip\n codec preference 1 g711ulaw\n codec preference 2 g729r8", platform="Cisco CUBE"))
        fixes.append(FixItem(priority=2, action="Check CUCM Region codec settings",
            detail="System > Region > ensure G.711 is enabled for the SIP trunk region.", platform="Cisco CUCM"))
    elif "AUDIOCODES" in platform:
        fixes.append(FixItem(priority=1, action="Add G.711 to AudioCodes Coders list",
            detail="Gateway > VoIP > Media > Coders — add PCMU as first preference.", platform="AudioCodes"))
    else:
        fixes.append(FixItem(priority=1, action="Add G.711 (PCMU) as first codec preference",
            detail="Ensure G.711 μ-law is offered. Most PSTN carriers require it.", platform="Generic"))

    config = None
    if "CUBE" in platform or "CISCO" in platform:
        config = "dial-peer voice 100 voip\n codec preference 1 g711ulaw\n codec preference 2 g729r8"

    return RCAResult(
        root_cause=f"Codec mismatch — INVITE offered [{codec_str}] which the remote endpoint does not support",
        root_cause_detail=detail,
        failure_layer="MEDIA", failure_location="SDP negotiation at remote endpoint",
        confidence=92 if offer_codecs else 75,
        contributing_factors=["No common codec between offer and answer", "Carrier likely requires G.711 (PCMU)"],
        recommended_fixes=fixes, config_snippet=config,
    )


def _rca_503(messages, platform) -> RCAResult:
    """Precise RCA for 503 Service Unavailable."""
    has_retry_after = any("Retry-After" in m.raw_message for m in messages if m.response_code == 503)

    return RCAResult(
        root_cause="SIP trunk or destination server is unavailable — immediate 503 rejection",
        root_cause_detail="The remote server returned 503 Service Unavailable, indicating it cannot process requests. "
            + ("A Retry-After header was included, suggesting temporary overload." if has_retry_after else "No Retry-After header — may indicate a hard failure or outage."),
        failure_layer="CAPACITY", failure_location="Remote SIP trunk/gateway",
        confidence=90,
        contributing_factors=["SIP trunk capacity may be exhausted", "Carrier may be experiencing outage", "SBC may be overloaded or license-limited"],
        recommended_fixes=[
            FixItem(priority=1, action="Check SIP trunk status", detail="Verify trunk registration and capacity. Try backup trunk if available.", platform="Generic"),
            FixItem(priority=2, action="Contact carrier NOC", detail="If carrier trunk, escalate to carrier NOC with Call-ID and timestamps.", platform="Generic"),
        ],
        escalation_needed=True, escalation_reason="503 indicates service outage — carrier or trunk capacity issue",
    )


def _rca_auth(error, messages, platform) -> RCAResult:
    """Precise RCA for 401/403 authentication/policy failures."""
    is_register = any(m.method == "REGISTER" for m in messages)
    repeated_401 = sum(1 for m in messages if m.response_code == 401) > 1

    if error.error_code == 403:
        if is_register and repeated_401:
            return RCAResult(
                root_cause="SIP registration authentication failure — credentials rejected after challenge",
                root_cause_detail="The device attempted to register, received a 401 challenge, provided credentials, but was ultimately rejected with 403 Forbidden. The authentication hash did not match — wrong username or password.",
                failure_layer="AUTHENTICATION", failure_location="SIP registrar server",
                confidence=95, contributing_factors=["Invalid username or password", "Realm mismatch possible"],
                recommended_fixes=[
                    FixItem(priority=1, action="Verify SIP credentials", detail="Check username and password on the endpoint match the server's user database.", platform="Generic"),
                ],
            )
        return RCAResult(
            root_cause="Call blocked by security policy (403 Forbidden)",
            root_cause_detail="The server rejected the request with 403. This is a policy block, not an auth issue.",
            failure_layer="POLICY", failure_location="SIP server policy engine",
            confidence=80, contributing_factors=["ACL/policy blocking", "Toll restriction", "Number format rejected"],
            recommended_fixes=[FixItem(priority=1, action="Review calling restrictions and ACLs", detail="Check CSS/Partition in CUCM, or ACL rules on SBC.", platform="Generic")],
        )

    return RCAResult(
        root_cause="SIP authentication failure (401 Unauthorized)",
        root_cause_detail="Authentication credentials were not accepted. " + ("Multiple 401 responses indicate repeated auth failures." if repeated_401 else ""),
        failure_layer="AUTHENTICATION", failure_location="SIP server",
        confidence=85, contributing_factors=["Wrong credentials", "Realm mismatch"],
        recommended_fixes=[FixItem(priority=1, action="Verify SIP auth credentials", detail="Check username, password, and realm on the endpoint.", platform="Generic")],
    )


def _rca_408(platform) -> RCAResult:
    return RCAResult(
        root_cause="SIP request timed out — destination unreachable",
        root_cause_detail="No response received within SIP Timer B (32 seconds). The destination is unreachable, a firewall is dropping packets, or the endpoint is down.",
        failure_layer="NETWORK", failure_location="Network path to destination",
        confidence=75, contributing_factors=["Destination offline", "Firewall blocking SIP", "DNS resolution failure"],
        recommended_fixes=[
            FixItem(priority=1, action="Verify network connectivity", detail="Ping/traceroute to destination IP. Check firewall rules for UDP/TCP 5060-5061.", platform="Generic"),
            FixItem(priority=2, action="Check remote endpoint status", detail="Confirm destination device is powered on and registered.", platform="Generic"),
        ],
    )


def _rca_404(platform) -> RCAResult:
    return RCAResult(
        root_cause="Destination number/URI not found (404 Not Found)",
        root_cause_detail="The called number does not exist on the remote system. Check that the number is provisioned and the dial plan routes correctly.",
        failure_layer="SIGNALING", failure_location="Remote server dial plan",
        confidence=85, contributing_factors=["Number not provisioned", "Dial plan misconfiguration", "Wrong SIP trunk domain"],
        recommended_fixes=[
            FixItem(priority=1, action="Verify called number exists", detail="Check number in the remote system's directory or route plan.", platform="Generic"),
            FixItem(priority=2, action="Check number transformations", detail="Review calling/called number transformation patterns on the SIP trunk.", platform="Cisco CUCM"),
        ],
    )


def _rca_480(messages, platform) -> RCAResult:
    """Precise RCA for 480 Temporarily Unavailable."""
    # Check if there's a Reason header with more info
    reason_info = ""
    for m in messages:
        if m.response_code == 480 and "reason" in m.raw_message.lower():
            reason_info = " A Reason header was included, suggesting the device went offline or entered DND."

    fixes = [
        FixItem(priority=1, action="Check endpoint registration status",
            detail="Verify the destination device is registered. On CUCM: show risdb query phone.",
            platform="Cisco CUCM" if "CISCO" in (platform or "") else "Generic"),
        FixItem(priority=2, action="Check DND and forwarding settings",
            detail="User may have Do Not Disturb enabled or Call Forward All active.",
            platform="Generic"),
    ]
    if "CUCM" in (platform or ""):
        fixes.append(FixItem(priority=3, action="Check Line Group / Hunt List",
            detail="If using hunt groups, verify hunt list members are registered and available.",
            platform="Cisco CUCM"))

    return RCAResult(
        root_cause="Called endpoint temporarily unavailable (480)",
        root_cause_detail=(
            "The destination device or user is temporarily unavailable. This typically means the phone "
            "is not registered, the user has DND enabled, or all lines are busy."
            + reason_info
        ),
        failure_layer="SIGNALING", failure_location="Destination endpoint or registrar",
        confidence=82,
        contributing_factors=["Device not registered", "DND enabled", "All lines busy", "Registration expired"],
        recommended_fixes=fixes,
    )


def _rca_482(messages, platform) -> RCAResult:
    """Precise RCA for 482 Loop Detected."""
    # Count Via headers in the INVITE to see hop count
    via_count = 0
    for m in messages:
        if m.method == "INVITE" and m.type == MessageType.REQUEST:
            via_count = len(m.via_headers)
            break

    fixes = [FixItem(priority=1, action="Audit routing / dial plan for loops",
        detail="Check each hop in the Via headers. A loop means a proxy saw its own address in the Via chain.",
        platform="Generic")]
    if "CUCM" in (platform or ""):
        fixes.append(FixItem(priority=2, action="Check CSS/Partition chains",
            detail="In CUCM, review CSS → Route Pattern → Route List → Route Group → SIP Trunk for circular references.",
            platform="Cisco CUCM"))

    return RCAResult(
        root_cause="SIP routing loop detected (482 Loop Detected)",
        root_cause_detail=(
            f"The request looped back through a proxy that already processed it (Via count: {via_count}). "
            "This is a dial plan configuration error where the route bounces between two or more nodes."
        ),
        failure_layer="SIGNALING", failure_location="SIP proxy routing chain",
        confidence=90,
        contributing_factors=["Circular route plan", "CSS/Partition misconfiguration", "Mismatched route group"],
        recommended_fixes=fixes,
    )


def _rca_484(messages, platform) -> RCAResult:
    """Precise RCA for 484 Address Incomplete."""
    # Extract the called number for context
    called_number = ""
    for m in messages:
        if m.method == "INVITE" and m.type == MessageType.REQUEST:
            if m.to_header:
                import re
                match = re.search(r"<sip:([^>]+)>", m.to_header)
                if match:
                    called_number = match.group(1).split("@")[0]
            break

    detail = (
        f"The dialed number '{called_number or 'unknown'}' was rejected as incomplete. "
        "The remote server expected more digits. This usually means the number needs a "
        "country code prefix, area code, or different number format."
    )

    fixes = [
        FixItem(priority=1, action="Add country code or adjust number format",
            detail="Ensure called number includes full E.164 format (+1XXXXXXXXXX for US). "
                   "Check calling/called party transformation patterns.",
            platform="Generic"),
    ]
    if "CUBE" in (platform or "") or "CUCM" in (platform or ""):
        fixes.append(FixItem(priority=2, action="Review called-number transformation on SIP trunk",
            detail="CUCM > SIP Trunk > Called Party Transformation Pattern. Ensure prefix digits are correct.",
            platform="Cisco CUCM"))

    return RCAResult(
        root_cause=f"Dialed number incomplete (484 Address Incomplete): '{called_number}'",
        root_cause_detail=detail,
        failure_layer="SIGNALING", failure_location="Remote switch / carrier dial plan",
        confidence=88,
        contributing_factors=["Missing country code/area code", "Wrong number transformation", "Overlap dialing issue"],
        recommended_fixes=fixes,
    )


def _rca_486(messages, platform) -> RCAResult:
    """Precise RCA for 486 Busy Here."""
    # Check if there's call waiting or forwarding hints
    has_diversion = any("diversion" in m.raw_message.lower() for m in messages)

    detail = (
        "The called endpoint returned 486 Busy Here — the user is already on an active call "
        "and has no available line appearances."
    )
    if has_diversion:
        detail += " A Diversion header was present, suggesting the call was forwarded before reaching the busy endpoint."

    factors = ["User on another call", "Single-line phone", "No Call Waiting enabled"]
    fixes = [
        FixItem(priority=1, action="Enable Call Waiting on the endpoint",
            detail="If the user should receive calls while busy, enable Call Waiting on their line.",
            platform="Generic"),
        FixItem(priority=2, action="Configure Call Forward Busy",
            detail="Set up Call Forward Busy to voicemail or another extension.",
            platform="Generic"),
    ]
    if "CUCM" in (platform or ""):
        fixes.append(FixItem(priority=3, action="Add more line appearances",
            detail="CUCM > Device > Phone > add additional lines (DN) to allow concurrent calls.",
            platform="Cisco CUCM"))
        factors.append("Insufficient line appearances on CUCM")

    return RCAResult(
        root_cause="Called party busy (486 Busy Here)",
        root_cause_detail=detail,
        failure_layer="SIGNALING", failure_location="Destination endpoint",
        confidence=92,
        contributing_factors=factors,
        recommended_fixes=fixes,
    )


def _rca_500(messages, platform) -> RCAResult:
    """Precise RCA for 500 Server Internal Error."""
    # Check for any Warning or Reason headers that give more info
    warning_info = ""
    for m in messages:
        if m.response_code == 500:
            raw_lower = m.raw_message.lower()
            if "warning:" in raw_lower:
                warning_info = " A Warning header is present — check it for details about the internal error."
            if "transaction" in raw_lower:
                warning_info += " The error mentions a transaction issue — possible database or state corruption."

    fixes = [
        FixItem(priority=1, action="Check server logs for exceptions",
            detail="Review the call processing server logs at the time of failure for stack traces or error messages.",
            platform="Generic"),
        FixItem(priority=2, action="Verify server resource usage",
            detail="Check CPU, memory, and disk usage. High load can cause 500 errors.",
            platform="Generic"),
    ]
    if "CUCM" in (platform or ""):
        fixes = [
            FixItem(priority=1, action="Check CUCM RTMT for alarms",
                detail="Open RTMT > SysLog Viewer > filter by timestamp of failure. Look for CallManager service exceptions.",
                platform="Cisco CUCM"),
            FixItem(priority=2, action="Check MTP/Transcoder resources",
                detail="CUCM > Media Resources > check MTP and Transcoder pools. 500 can occur when media resources are exhausted.",
                platform="Cisco CUCM"),
            FixItem(priority=3, action="Restart CallManager service if persistent",
                detail="Utils service restart Cisco CallManager (last resort, causes brief outage).",
                platform="Cisco CUCM"),
        ]

    return RCAResult(
        root_cause="Server internal error (500) — call processing failure on remote server",
        root_cause_detail=(
            "The SIP server encountered an internal error while processing the request. "
            "This is a server-side issue — not a client configuration problem."
            + warning_info
        ),
        failure_layer="SIGNALING", failure_location="SIP server / call processing engine",
        confidence=78,
        contributing_factors=["Server software bug", "Resource exhaustion (CPU/memory)", "Database/state error", "MTP/transcoder unavailable"],
        recommended_fixes=fixes,
        escalation_needed=True,
        escalation_reason="500 Internal Server Error requires server-side investigation",
    )


def _rca_srtp_mismatch(mm, platform) -> RCAResult:
    return RCAResult(
        root_cause="SRTP/RTP mismatch — one side uses encryption, the other does not",
        root_cause_detail=mm.description + " This causes one-way audio or no audio even though the call connected with 200 OK.",
        failure_layer="MEDIA", failure_location="Media encryption negotiation",
        confidence=93, contributing_factors=["SRTP offered but RTP answered", "Encryption not configured consistently"],
        recommended_fixes=[
            FixItem(priority=1, action="Match encryption settings on both sides", detail="Either enable SRTP on the non-SRTP side, or configure the SRTP side to fall back to RTP.", platform="Generic"),
        ],
    )


def _severity_rank(severity: Severity) -> int:
    return {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}.get(severity, 0)
