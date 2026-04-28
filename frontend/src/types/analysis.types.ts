/**
 * TypeScript interfaces for SIP Sherlock analysis data.
 * Mirrors the backend Pydantic schemas.
 */

export interface SIPMessage {
  index: number;
  timestamp: string | null;
  direction: 'SENT' | 'RECEIVED' | 'UNKNOWN';
  type: 'REQUEST' | 'RESPONSE';
  method: string | null;
  request_uri: string | null;
  response_code: number | null;
  response_text: string | null;
  from_header: string;
  to_header: string;
  call_id: string;
  cseq: string;
  cseq_method: string | null;
  via_headers: string[];
  contact: string | null;
  user_agent: string | null;
  sdp_body: string | null;
  raw_message: string;
}

export interface CodecDetail {
  pt: number;
  name: string;
  rate: number | null;
  channels: number | null;
  fmtp: string | null;
}

export interface ParsedSDP {
  codecs: string[];
  codec_details: CodecDetail[];
  direction: string;
  connection_ip: string;
  media_port: number;
  media_protocol: string | null;
  has_srtp: boolean;
  crypto_lines: string[];
  dtmf_payload_type: number | null;
  dtmf_method: string | null;
  ptime: number | null;
  bandwidth: string | null;
  is_fax: boolean;
  is_on_hold: boolean;
  hold_method: string | null;
  raw_sdp: string | null;
}

export interface SDPMismatch {
  type: string;
  severity: string;
  field: string;
  description: string;
  offer_value: string | null;
  answer_value: string | null;
  explanation: string;
}

export interface SDPPair {
  offer_message_index: number;
  answer_message_index: number | null;
  offer_sdp: ParsedSDP;
  answer_sdp: ParsedSDP | null;
  mismatches: SDPMismatch[];
}

export interface SIPError {
  message_index: number;
  error_code: number | null;
  error_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  engineer_explanation: string;
}

export interface CallTimeline {
  call_id: string;
  calling_party: string;
  calling_ip: string | null;
  called_party: string;
  called_ip: string | null;
  call_start: string | null;
  call_answered: boolean;
  call_answer_time: string | null;
  call_end: string | null;
  duration_seconds: number | null;
  duration_estimated: boolean;
  final_disposition: 'ANSWERED' | 'FAILED' | 'BUSY' | 'CANCELLED' | 'UNAVAILABLE' | 'NOT_FOUND' | 'REJECTED' | 'AUTH_REQUIRED' | 'UNKNOWN';
  failure_point: string | null;
}

export interface LadderMessage {
  index: number;
  timestamp: string | null;
  from_participant: string;
  to_participant: string;
  label: string;
  type: 'request' | 'response' | 'retransmission';
  severity: 'normal' | 'warning' | 'error' | 'critical';
  has_sdp: boolean;
  sdp_summary: string | null;
  raw_message: string;
}

export interface LadderData {
  participants: string[];
  messages: LadderMessage[];
}

export interface FixItem {
  priority: number;
  action: string;
  detail: string;
  platform: string;
}

export interface RCAResult {
  root_cause: string;
  root_cause_detail: string;
  failure_layer: string;
  failure_location: string;
  confidence: number;
  contributing_factors: string[];
  recommended_fixes: FixItem[];
  config_snippet: string | null;
  escalation_needed: boolean;
  escalation_reason: string | null;
}

export interface AnalysisResult {
  analysis_id: string;
  input_type: string;
  parsed_message_count: number;
  call_timeline: CallTimeline;
  ladder_data: LadderData;
  detected_errors: SIPError[];
  sdp_pairs: SDPPair[];
  rca: RCAResult;
  detected_platform: string;
  processing_time_ms: number;
  analyzed_at: string;
}
