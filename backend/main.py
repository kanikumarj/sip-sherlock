"""
SIP Sherlock — FastAPI Backend
Main application entry point with all API endpoints.
"""

from __future__ import annotations
import os
import time
import uuid
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from knowledge.sip_knowledge import detect_platform

from models.schemas import (
    AnalysisResult, TextAnalysisRequest, RCAResult,
)
from parser.sip_parser import parse_sip_text, group_by_call_id, select_primary_call, get_all_calls_summary, get_primary_call
from parser.pcap_parser import extract_sip_from_pcap
from analyzer.analysis_engine import (
    detect_errors, extract_sdp_pairs, build_call_timeline, build_ladder_data,
)
from analyzer.rca_engine import generate_rca
from analyzer.output_validator import AnalysisQualityValidator

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_TEXT_SIZE = 500 * 1024
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE_MB", "10")) * 1024 * 1024
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "http://localhost:5173")

validator = AnalysisQualityValidator()

# ─── Sample Fixtures (5 Real-World Scenarios) ────────────────────

SAMPLE_FIXTURES = {
    "cucm_488": """INVITE sip:+14085559876@att-sip.example.com SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-524287-1
From: <sip:+14155551234@10.10.10.1>;tag=gK0a1b2c3
To: <sip:+14085559876@att-sip.example.com>
Call-ID: a1b2c3d4-1234-5678@10.10.10.1
CSeq: 1 INVITE
Contact: <sip:+14155551234@10.10.10.1:5060;transport=udp>
Content-Type: application/sdp
Content-Length: 220
Max-Forwards: 69
User-Agent: Cisco-CUBE/16.12

v=0
o=CiscoSystemsSIP-GW-UserAgent 1234 1 IN IP4 10.10.10.1
s=SIP Call
c=IN IP4 10.10.10.1
t=0 0
m=audio 16634 RTP/AVP 18 101
a=rtpmap:18 G729/8000
a=fmtp:18 annexb=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
a=ptime:20

---

SIP/2.0 100 Trying
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-524287-1
From: <sip:+14155551234@10.10.10.1>;tag=gK0a1b2c3
To: <sip:+14085559876@att-sip.example.com>
Call-ID: a1b2c3d4-1234-5678@10.10.10.1
CSeq: 1 INVITE
Content-Length: 0

---

SIP/2.0 488 Not Acceptable Here
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-524287-1
From: <sip:+14155551234@10.10.10.1>;tag=gK0a1b2c3
To: <sip:+14085559876@att-sip.example.com>;tag=att-rej-001
Call-ID: a1b2c3d4-1234-5678@10.10.10.1
CSeq: 1 INVITE
Warning: 305 att-sip.example.com "Incompatible media format"
Content-Length: 0

---

ACK sip:+14085559876@att-sip.example.com SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK-524287-1
From: <sip:+14155551234@10.10.10.1>;tag=gK0a1b2c3
To: <sip:+14085559876@att-sip.example.com>;tag=att-rej-001
Call-ID: a1b2c3d4-1234-5678@10.10.10.1
CSeq: 1 ACK
Content-Length: 0""",

    "teams_drop": """INVITE sip:+12125551234@carrier.siptrunk.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKabc123
From: <sip:+14155551234@192.168.1.10>;tag=tag001
To: <sip:+12125551234@carrier.siptrunk.com>
Call-ID: call001@192.168.1.10
CSeq: 101 INVITE
Content-Type: application/sdp
Content-Length: 170

v=0
o=- 12345 1 IN IP4 192.168.1.10
s=-
c=IN IP4 192.168.1.10
t=0 0
m=audio 20000 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv

---

SIP/2.0 503 Service Unavailable
Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKabc123
From: <sip:+14155551234@192.168.1.10>;tag=tag001
To: <sip:+12125551234@carrier.siptrunk.com>;tag=srvtag
Call-ID: call001@192.168.1.10
CSeq: 101 INVITE
Retry-After: 60
Content-Length: 0

---

ACK sip:+12125551234@carrier.siptrunk.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKabc123
From: <sip:+14155551234@192.168.1.10>;tag=tag001
To: <sip:+12125551234@carrier.siptrunk.com>;tag=srvtag
Call-ID: call001@192.168.1.10
CSeq: 101 ACK
Content-Length: 0""",

    "sbc_timeout": """REGISTER sip:10.10.10.5 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.50:5060;branch=z9hG4bKreg01
From: <sip:1001@10.10.10.5>;tag=reg-tag-001
To: <sip:1001@10.10.10.5>
Call-ID: register-001@10.10.10.50
CSeq: 1 REGISTER
Contact: <sip:1001@10.10.10.50:5060>
Expires: 3600
Content-Length: 0

---

SIP/2.0 401 Unauthorized
Via: SIP/2.0/UDP 10.10.10.50:5060;branch=z9hG4bKreg01
From: <sip:1001@10.10.10.5>;tag=reg-tag-001
To: <sip:1001@10.10.10.5>
Call-ID: register-001@10.10.10.50
CSeq: 1 REGISTER
WWW-Authenticate: Digest realm="10.10.10.5",nonce="abc123xyz",algorithm=MD5,qop="auth"
Content-Length: 0

---

REGISTER sip:10.10.10.5 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.50:5060;branch=z9hG4bKreg02
From: <sip:1001@10.10.10.5>;tag=reg-tag-001
To: <sip:1001@10.10.10.5>
Call-ID: register-001@10.10.10.50
CSeq: 2 REGISTER
Contact: <sip:1001@10.10.10.50:5060>
Authorization: Digest username="1001",realm="10.10.10.5",nonce="abc123xyz",uri="sip:10.10.10.5",response="wronghash123",algorithm=MD5
Expires: 3600
Content-Length: 0

---

SIP/2.0 403 Forbidden
Via: SIP/2.0/UDP 10.10.10.50:5060;branch=z9hG4bKreg02
From: <sip:1001@10.10.10.5>;tag=reg-tag-001
To: <sip:1001@10.10.10.5>
Call-ID: register-001@10.10.10.50
CSeq: 2 REGISTER
Content-Length: 0""",

    "srtp_mismatch": """INVITE sip:+14085559876@10.20.20.1:5060 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKsrtp01
From: <sip:1001@10.10.10.1>;tag=srtp-tag
To: <sip:+14085559876@10.20.20.1>
Call-ID: srtp-mismatch-001@10.10.10.1
CSeq: 101 INVITE
Content-Type: application/sdp
Content-Length: 260

v=0
o=- 1234 1 IN IP4 10.10.10.1
s=SIP Call
c=IN IP4 10.10.10.1
t=0 0
m=audio 20000 RTP/SAVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKys+fgghjklmno==
a=sendrecv

---

SIP/2.0 200 OK
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKsrtp01
From: <sip:1001@10.10.10.1>;tag=srtp-tag
To: <sip:+14085559876@10.20.20.1>;tag=rtp-side-tag
Call-ID: srtp-mismatch-001@10.10.10.1
CSeq: 101 INVITE
Content-Type: application/sdp
Content-Length: 170

v=0
o=- 9876 1 IN IP4 10.20.20.1
s=SIP Call
c=IN IP4 10.20.20.1
t=0 0
m=audio 22000 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv

---

ACK sip:+14085559876@10.20.20.1:5060 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKsrtpack
From: <sip:1001@10.10.10.1>;tag=srtp-tag
To: <sip:+14085559876@10.20.20.1>;tag=rtp-side-tag
Call-ID: srtp-mismatch-001@10.10.10.1
CSeq: 101 ACK
Content-Length: 0

---

BYE sip:+14085559876@10.20.20.1:5060 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKsrtpbye
From: <sip:1001@10.10.10.1>;tag=srtp-tag
To: <sip:+14085559876@10.20.20.1>;tag=rtp-side-tag
Call-ID: srtp-mismatch-001@10.10.10.1
CSeq: 102 BYE
Content-Length: 0

---

SIP/2.0 200 OK
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKsrtpbye
From: <sip:1001@10.10.10.1>;tag=srtp-tag
To: <sip:+14085559876@10.20.20.1>;tag=rtp-side-tag
Call-ID: srtp-mismatch-001@10.10.10.1
CSeq: 102 BYE
Content-Length: 0""",

    "success": """INVITE sip:+14085559876@10.10.10.2:5060 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKsucc01
From: <sip:1001@10.10.10.1>;tag=success-tag
To: <sip:+14085559876@10.10.10.2>
Call-ID: success-call-001@10.10.10.1
CSeq: 101 INVITE
Contact: <sip:1001@10.10.10.1:5060>
Content-Type: application/sdp
Content-Length: 180

v=0
o=- 1001 1 IN IP4 10.10.10.1
s=SIP Call
c=IN IP4 10.10.10.1
t=0 0
m=audio 20000 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=ptime:20

---

SIP/2.0 100 Trying
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKsucc01
From: <sip:1001@10.10.10.1>;tag=success-tag
To: <sip:+14085559876@10.10.10.2>
Call-ID: success-call-001@10.10.10.1
CSeq: 101 INVITE
Content-Length: 0

---

SIP/2.0 180 Ringing
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKsucc01
From: <sip:1001@10.10.10.1>;tag=success-tag
To: <sip:+14085559876@10.10.10.2>;tag=ringing-tag
Call-ID: success-call-001@10.10.10.1
CSeq: 101 INVITE
Content-Length: 0

---

SIP/2.0 200 OK
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKsucc01
From: <sip:1001@10.10.10.1>;tag=success-tag
To: <sip:+14085559876@10.10.10.2>;tag=answered-tag
Call-ID: success-call-001@10.10.10.1
CSeq: 101 INVITE
Contact: <sip:+14085559876@10.10.10.2:5060>
Content-Type: application/sdp
Content-Length: 160

v=0
o=- 2002 1 IN IP4 10.10.10.2
s=SIP Call
c=IN IP4 10.10.10.2
t=0 0
m=audio 22000 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=ptime:20

---

ACK sip:+14085559876@10.10.10.2:5060 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKsucc01ack
From: <sip:1001@10.10.10.1>;tag=success-tag
To: <sip:+14085559876@10.10.10.2>;tag=answered-tag
Call-ID: success-call-001@10.10.10.1
CSeq: 101 ACK
Content-Length: 0

---

BYE sip:+14085559876@10.10.10.2:5060 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKbye01
From: <sip:1001@10.10.10.1>;tag=success-tag
To: <sip:+14085559876@10.10.10.2>;tag=answered-tag
Call-ID: success-call-001@10.10.10.1
CSeq: 102 BYE
Content-Length: 0

---

SIP/2.0 200 OK
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKbye01
From: <sip:1001@10.10.10.1>;tag=success-tag
To: <sip:+14085559876@10.10.10.2>;tag=answered-tag
Call-ID: success-call-001@10.10.10.1
CSeq: 102 BYE
Content-Length: 0""",

    "busy_486": """INVITE sip:+14085559876@10.10.10.2:5060 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKbusy01
From: <sip:1001@10.10.10.1>;tag=busy-tag
To: <sip:+14085559876@10.10.10.2>
Call-ID: busy-call-001@10.10.10.1
CSeq: 101 INVITE
Content-Type: application/sdp
Content-Length: 180
User-Agent: Cisco-CUCM12.5

v=0
o=- 1001 1 IN IP4 10.10.10.1
s=SIP Call
c=IN IP4 10.10.10.1
t=0 0
m=audio 20000 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv

---

SIP/2.0 100 Trying
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKbusy01
From: <sip:1001@10.10.10.1>;tag=busy-tag
To: <sip:+14085559876@10.10.10.2>
Call-ID: busy-call-001@10.10.10.1
CSeq: 101 INVITE
Content-Length: 0

---

SIP/2.0 486 Busy Here
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKbusy01
From: <sip:1001@10.10.10.1>;tag=busy-tag
To: <sip:+14085559876@10.10.10.2>;tag=busy-resp
Call-ID: busy-call-001@10.10.10.1
CSeq: 101 INVITE
Content-Length: 0

---

ACK sip:+14085559876@10.10.10.2:5060 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bKbusy01
From: <sip:1001@10.10.10.1>;tag=busy-tag
To: <sip:+14085559876@10.10.10.2>;tag=busy-resp
Call-ID: busy-call-001@10.10.10.1
CSeq: 101 ACK
Content-Length: 0""",

    "unavailable_480": """INVITE sip:2001@10.10.10.5:5060 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK480-01
From: <sip:1001@10.10.10.1>;tag=ua-tag-480
To: <sip:2001@10.10.10.5>
Call-ID: unavail-001@10.10.10.1
CSeq: 101 INVITE
Content-Type: application/sdp
Content-Length: 170

v=0
o=- 1001 1 IN IP4 10.10.10.1
s=SIP Call
c=IN IP4 10.10.10.1
t=0 0
m=audio 20000 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv

---

SIP/2.0 480 Temporarily Unavailable
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK480-01
From: <sip:1001@10.10.10.1>;tag=ua-tag-480
To: <sip:2001@10.10.10.5>;tag=unavail-resp
Call-ID: unavail-001@10.10.10.1
CSeq: 101 INVITE
Content-Length: 0

---

ACK sip:2001@10.10.10.5:5060 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK480-01
From: <sip:1001@10.10.10.1>;tag=ua-tag-480
To: <sip:2001@10.10.10.5>;tag=unavail-resp
Call-ID: unavail-001@10.10.10.1
CSeq: 101 ACK
Content-Length: 0""",

    "server_error_500": """INVITE sip:+18005551234@carrier-gw.example.com SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK500-01
From: <sip:1001@10.10.10.1>;tag=tag-500
To: <sip:+18005551234@carrier-gw.example.com>
Call-ID: server-err-001@10.10.10.1
CSeq: 101 INVITE
Content-Type: application/sdp
Content-Length: 170
User-Agent: Cisco-CUCM12.5

v=0
o=- 1001 1 IN IP4 10.10.10.1
s=SIP Call
c=IN IP4 10.10.10.1
t=0 0
m=audio 20000 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv

---

SIP/2.0 100 Trying
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK500-01
From: <sip:1001@10.10.10.1>;tag=tag-500
To: <sip:+18005551234@carrier-gw.example.com>
Call-ID: server-err-001@10.10.10.1
CSeq: 101 INVITE
Content-Length: 0

---

SIP/2.0 500 Internal Server Error
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK500-01
From: <sip:1001@10.10.10.1>;tag=tag-500
To: <sip:+18005551234@carrier-gw.example.com>;tag=err-resp
Call-ID: server-err-001@10.10.10.1
CSeq: 101 INVITE
Warning: 399 carrier-gw.example.com "Internal processing error"
Content-Length: 0

---

ACK sip:+18005551234@carrier-gw.example.com SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK500-01
From: <sip:1001@10.10.10.1>;tag=tag-500
To: <sip:+18005551234@carrier-gw.example.com>;tag=err-resp
Call-ID: server-err-001@10.10.10.1
CSeq: 101 ACK
Content-Length: 0""",

    "address_incomplete_484": """INVITE sip:9876@10.10.10.5:5060 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK484-01
From: <sip:1001@10.10.10.1>;tag=tag-484
To: <sip:9876@10.10.10.5>
Call-ID: addr-inc-001@10.10.10.1
CSeq: 101 INVITE
Content-Type: application/sdp
Content-Length: 170

v=0
o=- 1001 1 IN IP4 10.10.10.1
s=SIP Call
c=IN IP4 10.10.10.1
t=0 0
m=audio 20000 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv

---

SIP/2.0 484 Address Incomplete
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK484-01
From: <sip:1001@10.10.10.1>;tag=tag-484
To: <sip:9876@10.10.10.5>;tag=inc-resp
Call-ID: addr-inc-001@10.10.10.1
CSeq: 101 INVITE
Content-Length: 0

---

ACK sip:9876@10.10.10.5:5060 SIP/2.0
Via: SIP/2.0/UDP 10.10.10.1:5060;branch=z9hG4bK484-01
From: <sip:1001@10.10.10.1>;tag=tag-484
To: <sip:9876@10.10.10.5>;tag=inc-resp
Call-ID: addr-inc-001@10.10.10.1
CSeq: 101 ACK
Content-Length: 0""",
}

# ─── App Setup ────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🔍 SIP Sherlock v1.1.0 starting — Phase 1 Perfection Engine")
    # Startup self-test: verify parser works
    test_sip = "INVITE sip:test@10.0.0.1 SIP/2.0\nVia: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKtest\nFrom: <sip:caller@10.0.0.2>;tag=t\nTo: <sip:test@10.0.0.1>\nCall-ID: startup@10.0.0.2\nCSeq: 1 INVITE\nContent-Length: 0\n\nSIP/2.0 200 OK\nVia: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKtest\nFrom: <sip:caller@10.0.0.2>;tag=t\nTo: <sip:test@10.0.0.1>;tag=r\nCall-ID: startup@10.0.0.2\nCSeq: 1 INVITE\nContent-Length: 0"
    test_msgs = parse_sip_text(test_sip)
    if len(test_msgs) >= 2:
        logger.info(f"✅ Parser startup validation passed ({len(test_msgs)} messages)")
    else:
        logger.warning(f"⚠️ Parser self-test: expected >=2 messages, got {len(test_msgs)}")
    if not os.getenv("ANTHROPIC_API_KEY"):
        logger.warning("⚠️ ANTHROPIC_API_KEY not set — AI RCA will use deterministic fallback")
    else:
        logger.info("✅ Anthropic API key configured")
    yield
    logger.info("SIP Sherlock shutting down")

app = FastAPI(title="SIP Sherlock", description="AI-powered SIP log analysis", version="1.1.0", lifespan=lifespan)

_CORS_ORIGINS = [
    CORS_ORIGIN,
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:3000",
    # Vercel production & preview deployments
    "https://sip-sherlock.vercel.app",
    "https://sip-sherlock-kanikumarj.vercel.app",
]
# Allow any *.vercel.app preview URL via regex
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_origin_regex=r"https://sip-sherlock.*\.vercel\.app",
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.1.0", "phase": "Phase 1 Perfection"}


@app.get("/api/samples/{sample_id}")
async def get_sample(sample_id: str):
    if sample_id not in SAMPLE_FIXTURES:
        raise HTTPException(status_code=404, detail=f"Sample '{sample_id}' not found")
    return {"sip_text": SAMPLE_FIXTURES[sample_id]}


@app.get("/api/samples")
async def list_samples():
    return {"samples": list(SAMPLE_FIXTURES.keys())}


@app.post("/api/analyze/text", response_model=AnalysisResult)
async def analyze_text(request: TextAnalysisRequest):
    if len(request.sip_text.encode("utf-8")) > MAX_TEXT_SIZE:
        raise HTTPException(status_code=413, detail={
            "error": "INPUT_TOO_LARGE",
            "message": f"Input exceeds {MAX_TEXT_SIZE // 1024}KB limit",
            "hints": ["Try splitting large logs by Call-ID and analyzing each call separately"]
        })
    if not request.sip_text.strip():
        raise HTTPException(status_code=400, detail={
            "error": "EMPTY_INPUT",
            "message": "No SIP text provided",
            "hints": ["Paste your SIP trace, CUCM log, CUBE debug output, or SBC log"]
        })
    return await _run_analysis(request.sip_text, input_type="text")


@app.post("/api/analyze/file", response_model=AnalysisResult)
async def analyze_file(file: UploadFile = File(...)):
    filename = file.filename or ""
    allowed = {".log", ".txt", ".pcap", ".pcapng"}
    ext = next((e for e in allowed if filename.lower().endswith(e)), "")
    if not ext:
        raise HTTPException(status_code=400, detail={
            "error": "UNSUPPORTED_FILE_TYPE",
            "message": f"Unsupported file type. Allowed: {', '.join(allowed)}",
            "hints": [
                "Use .log or .txt for text-based SIP logs",
                "Use .pcap or .pcapng for Wireshark captures",
                "Try pasting the log content directly in the Paste tab"
            ]
        })
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail={
            "error": "FILE_TOO_LARGE",
            "message": f"File exceeds {MAX_FILE_SIZE // (1024*1024)}MB limit ({len(content) // 1024}KB received)",
            "hints": ["Try splitting large logs and uploading individual call traces"]
        })
    if ext in (".pcap", ".pcapng"):
        return await _run_analysis_from_pcap(content, filename=filename)
    text = content.decode("utf-8", errors="replace")
    return await _run_analysis(text, input_type="log")


async def _run_analysis(raw_text: str, input_type: str = "text") -> AnalysisResult:
    start_time = time.time()
    analysis_id = str(uuid.uuid4())

    all_messages = parse_sip_text(raw_text)
    if not all_messages:
        lines = [l for l in raw_text.splitlines() if l.strip()]
        first_preview = lines[0][:120] if lines else "(empty)"

        # Try to identify what format this might be
        format_hints = []
        if 'SIPServers' in raw_text or 'BroadWorks' in raw_text:
            format_hints.append("BroadWorks log detected — ensure SIP message blocks are included")
        if 'wireshark' in raw_text.lower() or 'frame' in raw_text.lower():
            format_hints.append("Wireshark export detected — export as 'SIP only' plain text")
        if '.pcap' in raw_text.lower():
            format_hints.append("Use the 'Upload File' tab to upload .pcap files directly")

        format_hints += [
            "Ensure file contains actual SIP messages (INVITE, BYE, 200 OK, etc.)",
            "Try selecting ONLY the SIP message block and pasting that",
            "Supported: raw SIP, CUCM, CUBE, AudioCodes, Ribbon, Asterisk, FreeSWITCH logs",
            "Try clicking a sample trace below to see the expected format",
        ]

        raise HTTPException(status_code=422, detail={
            "error": "NO_SIP_MESSAGES",
            "message": "No valid SIP messages found in the provided text.",
            "input_lines": len(lines),
            "first_line_detected": first_preview,
            "total_lines": len(lines),
            "hints": format_hints,
        })

    groups = group_by_call_id(all_messages)
    messages = select_primary_call(groups) if len(groups) > 1 else all_messages

    errors = detect_errors(messages)
    sdp_pairs = extract_sdp_pairs(messages)
    timeline = build_call_timeline(messages)
    ladder = build_ladder_data(messages)

    try:
        rca = await generate_rca(messages, errors, sdp_pairs, timeline)
    except Exception as e:
        logger.error(f"RCA failed: {e}")
        rca = RCAResult(root_cause="RCA error", root_cause_detail=str(e), failure_layer="SIGNALING", failure_location="Unknown", confidence=0)

    # Detect platform
    raw_combined = " ".join(m.raw_message for m in messages[:5])
    detected_plat = detect_platform(raw_combined) or "GENERIC"

    result = AnalysisResult(
        analysis_id=analysis_id, input_type=input_type,
        parsed_message_count=len(messages), call_timeline=timeline,
        ladder_data=ladder, detected_errors=errors, sdp_pairs=sdp_pairs,
        rca=rca, detected_platform=detected_plat,
        processing_time_ms=int((time.time() - start_time) * 1000),
        analyzed_at=datetime.now(timezone.utc).isoformat(),
    )

    # Run quality validator
    report = validator.validate(result)
    if not report.passed:
        logger.warning(f"Quality validation flags: {[f.code for f in report.flags]}")

    return result


async def _run_analysis_from_pcap(file_bytes: bytes, filename: str = "") -> AnalysisResult:
    start_time = time.time()
    try:
        messages = extract_sip_from_pcap(file_bytes)
    except Exception as e:
        raise HTTPException(status_code=422, detail={
            "error": "PCAP_PARSE_ERROR",
            "message": f"Could not parse PCAP file: {str(e)}",
            "hints": [
                "Ensure file is a valid Wireshark .pcap capture",
                "File must contain SIP traffic on port 5060 or 5061",
                "Try exporting from Wireshark as plain text and use Paste mode"
            ]
        })
    if not messages:
        raise HTTPException(status_code=422, detail={
            "error": "NO_SIP_MESSAGES",
            "message": f"No SIP messages found in '{filename or 'PCAP file'}'",
            "hints": [
                "Ensure the PCAP contains SIP traffic on port 5060 or 5061",
                "Try opening in Wireshark and exporting SIP messages as plain text",
                "Then paste the text export in the Paste tab"
            ]
        })

    errors = detect_errors(messages)
    sdp_pairs = extract_sdp_pairs(messages)
    timeline = build_call_timeline(messages)
    ladder = build_ladder_data(messages)

    try:
        rca = await generate_rca(messages, errors, sdp_pairs, timeline)
    except Exception as e:
        rca = RCAResult(root_cause="RCA error", root_cause_detail=str(e), failure_layer="SIGNALING", failure_location="Unknown", confidence=0)

    raw_combined = " ".join(m.raw_message for m in messages[:5])
    detected_plat = detect_platform(raw_combined) or "GENERIC"

    result = AnalysisResult(
        analysis_id=str(uuid.uuid4()), input_type="pcap",
        parsed_message_count=len(messages), call_timeline=timeline,
        ladder_data=ladder, detected_errors=errors, sdp_pairs=sdp_pairs,
        rca=rca, detected_platform=detected_plat,
        processing_time_ms=int((time.time() - start_time) * 1000),
        analyzed_at=datetime.now(timezone.utc).isoformat(),
    )

    report = validator.validate(result)
    if not report.passed:
        logger.warning(f"Quality validation flags: {[f.code for f in report.flags]}")

    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
