"""
RCA Engine Hardening Validation — Tests all critical spec rules.
"""
from parser.sip_parser import parse_sip_text
from analyzer.analysis_engine import detect_errors, extract_sdp_pairs, build_call_timeline
from analyzer.rca_engine import _fallback_rca

results = []

# ═══ TEST 1: SUCCESS + BYE + cause=16 → MUST be SUCCESSFUL, failure_layer=NONE ═══
success_log = (
    "INVITE sip:+14085559876@carrier.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-001\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from1\r\n"
    "To: <sip:+14085559876@carrier.com>\r\n"
    "Call-ID: success-001@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "Content-Type: application/sdp\r\n"
    "\r\n"
    "v=0\r\no=- 1 1 IN IP4 10.10.10.1\r\ns=-\r\nc=IN IP4 10.10.10.1\r\n"
    "t=0 0\r\nm=audio 20000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    "\r\n"
    "SIP/2.0 100 Trying\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-001\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from1\r\n"
    "To: <sip:+14085559876@carrier.com>\r\n"
    "Call-ID: success-001@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "\r\n"
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-001\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from1\r\n"
    "To: <sip:+14085559876@carrier.com>;tag=to1\r\n"
    "Call-ID: success-001@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "Content-Type: application/sdp\r\n"
    "\r\n"
    "v=0\r\no=- 1 1 IN IP4 172.16.0.1\r\ns=-\r\nc=IN IP4 172.16.0.1\r\n"
    "t=0 0\r\nm=audio 30000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    "\r\n"
    "ACK sip:+14085559876@172.16.0.1 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-ack\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from1\r\n"
    "To: <sip:+14085559876@carrier.com>;tag=to1\r\n"
    "Call-ID: success-001@10.10.10.1\r\n"
    "CSeq: 1 ACK\r\n"
    "\r\n"
    "BYE sip:+12125551234@10.10.10.1 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 172.16.0.1:5060;branch=z9hG4bK-bye\r\n"
    "From: <sip:+14085559876@carrier.com>;tag=to1\r\n"
    "To: <sip:+12125551234@10.10.10.1>;tag=from1\r\n"
    "Call-ID: success-001@10.10.10.1\r\n"
    "CSeq: 2 BYE\r\n"
    "Reason: Q.850;cause=16;text=\"Normal call clearing\"\r\n"
    "\r\n"
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/UDP 172.16.0.1:5060;branch=z9hG4bK-bye\r\n"
    "From: <sip:+14085559876@carrier.com>;tag=to1\r\n"
    "To: <sip:+12125551234@10.10.10.1>;tag=from1\r\n"
    "Call-ID: success-001@10.10.10.1\r\n"
    "CSeq: 2 BYE\r\n"
)

msgs = parse_sip_text(success_log)
errs = detect_errors(msgs)
sdps = extract_sdp_pairs(msgs)
tl = build_call_timeline(msgs)
rca = _fallback_rca(msgs, errs, sdps, tl)

t1_pass = "success" in rca.root_cause.lower() and rca.failure_layer == "NONE"
results.append(("TEST 1: SUCCESS + BYE + cause=16", t1_pass))
print(f"{'PASS ✅' if t1_pass else 'FAIL ❌'} TEST 1: SUCCESS + BYE + cause=16")
print(f"  Root Cause: {rca.root_cause}")
print(f"  Failure Layer: {rca.failure_layer}")
print(f"  Confidence: {rca.confidence}")
print(f"  Detail: {rca.root_cause_detail[:150]}...")
print()


# ═══ TEST 2: 488 CODEC MISMATCH → failure_layer=MEDIA ═══
test_488 = (
    "INVITE sip:+14085559876@carrier.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-002\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from2\r\n"
    "To: <sip:+14085559876@carrier.com>\r\n"
    "Call-ID: fail-488@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "User-Agent: Cisco-SIPGateway/IOS\r\n"
    "Content-Type: application/sdp\r\n"
    "\r\n"
    "v=0\r\no=- 1 1 IN IP4 10.10.10.1\r\ns=-\r\nc=IN IP4 10.10.10.1\r\n"
    "t=0 0\r\nm=audio 20000 RTP/AVP 18\r\na=rtpmap:18 G729/8000\r\n"
    "\r\n"
    "SIP/2.0 100 Trying\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-002\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from2\r\n"
    "To: <sip:+14085559876@carrier.com>\r\n"
    "Call-ID: fail-488@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "\r\n"
    "SIP/2.0 488 Not Acceptable Here\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-002\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from2\r\n"
    "To: <sip:+14085559876@carrier.com>;tag=to2\r\n"
    "Call-ID: fail-488@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "\r\n"
    "ACK sip:+14085559876@carrier.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-ack2\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from2\r\n"
    "To: <sip:+14085559876@carrier.com>;tag=to2\r\n"
    "Call-ID: fail-488@10.10.10.1\r\n"
    "CSeq: 1 ACK\r\n"
)

msgs = parse_sip_text(test_488)
errs = detect_errors(msgs)
sdps = extract_sdp_pairs(msgs)
tl = build_call_timeline(msgs)
rca = _fallback_rca(msgs, errs, sdps, tl)

t2_pass = "488" in rca.root_cause or "codec" in rca.root_cause.lower()
results.append(("TEST 2: 488 Codec Mismatch", t2_pass))
print(f"{'PASS ✅' if t2_pass else 'FAIL ❌'} TEST 2: 488 Codec Mismatch")
print(f"  Root Cause: {rca.root_cause}")
print(f"  Failure Layer: {rca.failure_layer}")
print(f"  Confidence: {rca.confidence}")
print()


# ═══ TEST 3: 503 Service Unavailable → CAPACITY, escalation=true ═══
test_503 = (
    "INVITE sip:+14085559876@carrier.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-003\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from3\r\n"
    "To: <sip:+14085559876@carrier.com>\r\n"
    "Call-ID: fail-503@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "\r\n"
    "SIP/2.0 503 Service Unavailable\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-003\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from3\r\n"
    "To: <sip:+14085559876@carrier.com>;tag=to3\r\n"
    "Call-ID: fail-503@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
)

msgs = parse_sip_text(test_503)
errs = detect_errors(msgs)
sdps = extract_sdp_pairs(msgs)
tl = build_call_timeline(msgs)
rca = _fallback_rca(msgs, errs, sdps, tl)

t3_pass = "503" in rca.root_cause and rca.failure_layer == "CAPACITY" and rca.escalation_needed
results.append(("TEST 3: 503 Service Unavailable", t3_pass))
print(f"{'PASS ✅' if t3_pass else 'FAIL ❌'} TEST 3: 503 Service Unavailable")
print(f"  Root Cause: {rca.root_cause}")
print(f"  Failure Layer: {rca.failure_layer}")
print(f"  Escalation: {rca.escalation_needed}")
print()


# ═══ TEST 4: CANCEL → NOT a failure ═══
test_cancel = (
    "INVITE sip:+14085559876@carrier.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-004\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from4\r\n"
    "To: <sip:+14085559876@carrier.com>\r\n"
    "Call-ID: cancel-001@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "\r\n"
    "SIP/2.0 180 Ringing\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-004\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from4\r\n"
    "To: <sip:+14085559876@carrier.com>;tag=to4\r\n"
    "Call-ID: cancel-001@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "\r\n"
    "CANCEL sip:+14085559876@carrier.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-004\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from4\r\n"
    "To: <sip:+14085559876@carrier.com>\r\n"
    "Call-ID: cancel-001@10.10.10.1\r\n"
    "CSeq: 1 CANCEL\r\n"
    "\r\n"
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-004\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from4\r\n"
    "To: <sip:+14085559876@carrier.com>;tag=to4\r\n"
    "Call-ID: cancel-001@10.10.10.1\r\n"
    "CSeq: 1 CANCEL\r\n"
    "\r\n"
    "SIP/2.0 487 Request Terminated\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-004\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from4\r\n"
    "To: <sip:+14085559876@carrier.com>;tag=to4\r\n"
    "Call-ID: cancel-001@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
)

msgs = parse_sip_text(test_cancel)
errs = detect_errors(msgs)
sdps = extract_sdp_pairs(msgs)
tl = build_call_timeline(msgs)
rca = _fallback_rca(msgs, errs, sdps, tl)

t4_pass = "cancel" in rca.root_cause.lower() and rca.failure_layer == "NONE"
results.append(("TEST 4: CANCEL (not failure)", t4_pass))
print(f"{'PASS ✅' if t4_pass else 'FAIL ❌'} TEST 4: CANCEL (not failure)")
print(f"  Root Cause: {rca.root_cause}")
print(f"  Failure Layer: {rca.failure_layer}")
print(f"  Confidence: {rca.confidence}")
print()


# ═══ TEST 5: Short call with BYE — NOT a failure (cause=16) ═══
test_short = (
    "INVITE sip:+14085559876@carrier.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-005\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from5\r\n"
    "To: <sip:+14085559876@carrier.com>\r\n"
    "Call-ID: short-001@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "Content-Type: application/sdp\r\n"
    "\r\n"
    "v=0\r\no=- 1 1 IN IP4 10.10.10.1\r\ns=-\r\nc=IN IP4 10.10.10.1\r\n"
    "t=0 0\r\nm=audio 20000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    "\r\n"
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-005\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from5\r\n"
    "To: <sip:+14085559876@carrier.com>;tag=to5\r\n"
    "Call-ID: short-001@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "Content-Type: application/sdp\r\n"
    "\r\n"
    "v=0\r\no=- 1 1 IN IP4 172.16.0.1\r\ns=-\r\nc=IN IP4 172.16.0.1\r\n"
    "t=0 0\r\nm=audio 30000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    "\r\n"
    "ACK sip:+14085559876@172.16.0.1 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-ack5\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from5\r\n"
    "To: <sip:+14085559876@carrier.com>;tag=to5\r\n"
    "Call-ID: short-001@10.10.10.1\r\n"
    "CSeq: 1 ACK\r\n"
    "\r\n"
    "BYE sip:+12125551234@10.10.10.1 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 172.16.0.1:5060;branch=z9hG4bK-bye5\r\n"
    "From: <sip:+14085559876@carrier.com>;tag=to5\r\n"
    "To: <sip:+12125551234@10.10.10.1>;tag=from5\r\n"
    "Call-ID: short-001@10.10.10.1\r\n"
    "CSeq: 2 BYE\r\n"
    "Reason: Q.850;cause=16;text=\"Normal call clearing\"\r\n"
)

msgs = parse_sip_text(test_short)
errs = detect_errors(msgs)
sdps = extract_sdp_pairs(msgs)
tl = build_call_timeline(msgs)
rca = _fallback_rca(msgs, errs, sdps, tl)

t5_pass = "success" in rca.root_cause.lower() and rca.failure_layer == "NONE"
results.append(("TEST 5: Short call + cause=16 = SUCCESS", t5_pass))
print(f"{'PASS ✅' if t5_pass else 'FAIL ❌'} TEST 5: Short call + cause=16 = SUCCESS")
print(f"  Root Cause: {rca.root_cause}")
print(f"  Failure Layer: {rca.failure_layer}")
print(f"  Confidence: {rca.confidence}")
print()


# ═══ TEST 6: 486 Busy Here ═══
test_486 = (
    "INVITE sip:+14085559876@carrier.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-006\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from6\r\n"
    "To: <sip:+14085559876@carrier.com>\r\n"
    "Call-ID: busy-001@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "\r\n"
    "SIP/2.0 486 Busy Here\r\n"
    "Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-006\r\n"
    "From: <sip:+12125551234@10.10.10.1>;tag=from6\r\n"
    "To: <sip:+14085559876@carrier.com>;tag=to6\r\n"
    "Call-ID: busy-001@10.10.10.1\r\n"
    "CSeq: 1 INVITE\r\n"
)

msgs = parse_sip_text(test_486)
errs = detect_errors(msgs)
sdps = extract_sdp_pairs(msgs)
tl = build_call_timeline(msgs)
rca = _fallback_rca(msgs, errs, sdps, tl)

t6_pass = "486" in rca.root_cause or "busy" in rca.root_cause.lower()
results.append(("TEST 6: 486 Busy Here", t6_pass))
print(f"{'PASS ✅' if t6_pass else 'FAIL ❌'} TEST 6: 486 Busy Here")
print(f"  Root Cause: {rca.root_cause}")
print(f"  Failure Layer: {rca.failure_layer}")
print()


# ═══════════════════════ SUMMARY ═══════════════════════
print("=" * 60)
passed = sum(1 for _, p in results if p)
total = len(results)
print(f"RESULTS: {passed}/{total} tests passed")
for name, passed_flag in results:
    print(f"  {'✅' if passed_flag else '❌'} {name}")
if passed == total:
    print("\n🎯 ALL TESTS PASSED — RCA Engine is spec-compliant!")
else:
    print(f"\n⚠️  {total - passed} test(s) FAILED — needs fixing!")
