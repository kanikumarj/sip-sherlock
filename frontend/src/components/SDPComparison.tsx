import { ArrowLeftRight, Check, X, AlertTriangle, Shield, ShieldOff, Volume2, Disc } from 'lucide-react';
import type { SDPPair, ParsedSDP } from '../types/analysis.types';

interface SDPComparisonProps {
  pairs: SDPPair[];
}

export default function SDPComparison({ pairs }: SDPComparisonProps) {
  if (pairs.length === 0) {
    return (
      <div className="bg-[#161B22] border border-[#30363D] rounded-xl p-6 animate-fade-in">
        <h3 className="text-lg font-semibold text-[#E6EDF3] mb-4 flex items-center gap-2">
          <ArrowLeftRight size={18} className="text-[#BC8CFF]" />
          SDP Analysis
        </h3>
        <div className="p-4 rounded-lg bg-[#8B949E]/10 border border-[#8B949E]/20">
          <p className="text-[#8B949E] text-sm">No SDP bodies found in this trace</p>
        </div>
      </div>
    );
  }

  const totalMismatches = pairs.reduce((sum, p) => sum + p.mismatches.length, 0);

  return (
    <div className="bg-[#161B22] border border-[#30363D] rounded-xl p-6 animate-fade-in">
      <div className="flex items-center justify-between mb-5">
        <h3 className="text-lg font-semibold text-[#E6EDF3] flex items-center gap-2">
          <ArrowLeftRight size={18} className="text-[#BC8CFF]" />
          SDP Analysis
          <span className="text-xs text-[#8B949E] font-normal ml-2">
            {pairs.length} pair{pairs.length !== 1 ? 's' : ''}
          </span>
        </h3>
        {totalMismatches > 0 ? (
          <span className="px-2 py-0.5 rounded text-xs font-medium bg-[#F85149]/15 text-[#F85149]">
            {totalMismatches} mismatch{totalMismatches !== 1 ? 'es' : ''}
          </span>
        ) : (
          <span className="px-2 py-0.5 rounded text-xs font-medium bg-[#3FB950]/15 text-[#3FB950]">
            All matched
          </span>
        )}
      </div>

      <div className="space-y-4">
        {pairs.map((pair, i) => (
          <PairCard key={i} pair={pair} index={i} />
        ))}
      </div>
    </div>
  );
}

function PairCard({ pair, index }: { pair: SDPPair; index: number }) {
  return (
    <div className="bg-[#0D1117] rounded-lg border border-[#30363D] overflow-hidden">
      <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
        <span className="text-sm text-[#E6EDF3] font-medium">
          Pair #{index + 1}
          <span className="text-[#8B949E] font-normal ml-2">
            msg #{pair.offer_message_index}
            {pair.answer_message_index != null ? ` → #${pair.answer_message_index}` : ' → No answer'}
          </span>
        </span>
        {pair.mismatches.length > 0 ? (
          <span className="flex items-center gap-1 text-xs text-[#F85149]">
            <AlertTriangle size={12} /> {pair.mismatches.length} issue{pair.mismatches.length !== 1 ? 's' : ''}
          </span>
        ) : (
          <span className="flex items-center gap-1 text-xs text-[#3FB950]">
            <Check size={12} /> Match
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-0">
        <div className="p-4 border-r border-[#30363D]">
          <p className="text-xs text-[#58A6FF] font-semibold mb-3 uppercase tracking-wider">Offer</p>
          <SDPDetail sdp={pair.offer_sdp} />
        </div>
        <div className="p-4">
          <p className="text-xs text-[#3FB950] font-semibold mb-3 uppercase tracking-wider">Answer</p>
          {pair.answer_sdp ? <SDPDetail sdp={pair.answer_sdp} /> : <p className="text-sm text-[#F85149] italic">No answer</p>}
        </div>
      </div>

      {pair.mismatches.length > 0 && (
        <div className="px-4 pb-4 space-y-2">
          {pair.mismatches.map((mm, j) => (
            <div key={j} className="flex items-start gap-2 p-3 rounded-lg bg-[#F85149]/5 border border-[#F85149]/15">
              <X size={14} className="text-[#F85149] mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-xs font-semibold text-[#F85149] mb-0.5">{mm.type.replace(/_/g, ' ').toUpperCase()}</p>
                <p className="text-xs text-[#E6EDF3]">{mm.description}</p>
                {mm.offer_value && mm.answer_value && (
                  <div className="mt-2 grid grid-cols-2 gap-2 text-[10px]">
                    <div className="bg-[#58A6FF]/10 rounded px-2 py-1">
                      <span className="text-[#58A6FF]">Offer:</span>{' '}
                      <span className="text-[#E6EDF3] font-mono">{mm.offer_value}</span>
                    </div>
                    <div className="bg-[#3FB950]/10 rounded px-2 py-1">
                      <span className="text-[#3FB950]">Answer:</span>{' '}
                      <span className="text-[#E6EDF3] font-mono">{mm.answer_value}</span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SDPDetail({ sdp }: { sdp: ParsedSDP }) {
  return (
    <div className="space-y-2.5 text-xs">
      {/* Codecs */}
      <div>
        <div className="flex items-center gap-1.5 mb-1.5">
          <Volume2 size={11} className="text-[#BC8CFF]" />
          <span className="text-[#8B949E] font-medium">Codecs</span>
        </div>
        {sdp.codec_details && sdp.codec_details.length > 0 ? (
          <div className="space-y-1">
            {sdp.codec_details.map((cd, i) => (
              <div key={i} className="flex items-center gap-2 px-2 py-1 bg-[#21262D] rounded">
                <span className="text-[#E6EDF3] font-semibold">{cd.name}</span>
                <span className="text-[#8B949E]">PT {cd.pt}</span>
                {cd.rate && <span className="text-[#8B949E]">{cd.rate / 1000}kHz</span>}
                {cd.fmtp && <span className="text-[#656D76] font-mono text-[9px]">{cd.fmtp}</span>}
              </div>
            ))}
          </div>
        ) : (
          <span className="text-[#E6EDF3]">{sdp.codecs.join(', ') || '—'}</span>
        )}
      </div>

      {/* Connection & Protocol */}
      <div className="grid grid-cols-2 gap-2">
        <div>
          <span className="text-[#8B949E]">IP:Port</span>
          <p className="text-[#E6EDF3] font-mono mt-0.5">{sdp.connection_ip || '—'}:{sdp.media_port || '—'}</p>
        </div>
        <div>
          <span className="text-[#8B949E]">Protocol</span>
          <p className="text-[#E6EDF3] font-mono mt-0.5">{sdp.media_protocol || '—'}</p>
        </div>
      </div>

      {/* Direction */}
      <div className="flex justify-between">
        <span className="text-[#8B949E]">Direction</span>
        <DirectionBadge direction={sdp.direction} isOnHold={sdp.is_on_hold} holdMethod={sdp.hold_method} />
      </div>

      {/* Security */}
      <div className="flex justify-between items-center">
        <span className="text-[#8B949E]">Security</span>
        <div className="flex items-center gap-1.5">
          {sdp.has_srtp ? (
            <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-[#3FB950]/15 text-[#3FB950]">
              <Shield size={10} /> SRTP
            </span>
          ) : (
            <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-[#D29922]/15 text-[#D29922]">
              <ShieldOff size={10} /> RTP
            </span>
          )}
        </div>
      </div>

      {/* DTMF */}
      <div className="flex justify-between">
        <span className="text-[#8B949E]">DTMF</span>
        <span className="text-[#E6EDF3]">{sdp.dtmf_method || '—'}{sdp.dtmf_payload_type ? ` (PT ${sdp.dtmf_payload_type})` : ''}</span>
      </div>

      {/* Ptime */}
      {sdp.ptime && (
        <div className="flex justify-between">
          <span className="text-[#8B949E]">Ptime</span>
          <span className="text-[#E6EDF3]">{sdp.ptime}ms</span>
        </div>
      )}

      {/* Bandwidth */}
      {sdp.bandwidth && (
        <div className="flex justify-between">
          <span className="text-[#8B949E]">Bandwidth</span>
          <span className="text-[#E6EDF3] font-mono">{sdp.bandwidth}</span>
        </div>
      )}

      {/* Fax */}
      {sdp.is_fax && (
        <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-[#D29922]/10 border border-[#D29922]/20">
          <Disc size={10} className="text-[#D29922]" />
          <span className="text-[#D29922] font-medium">T.38 Fax Detected</span>
        </div>
      )}

      {/* Crypto lines */}
      {sdp.crypto_lines && sdp.crypto_lines.length > 0 && (
        <div>
          <span className="text-[#8B949E]">Crypto</span>
          {sdp.crypto_lines.map((cl, i) => (
            <p key={i} className="text-[9px] text-[#656D76] font-mono mt-0.5 break-all">{cl}</p>
          ))}
        </div>
      )}
    </div>
  );
}

function DirectionBadge({ direction, isOnHold, holdMethod }: { direction: string; isOnHold: boolean; holdMethod: string | null }) {
  if (isOnHold) {
    return (
      <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-[#D29922]/15 text-[#D29922] text-[10px]">
        🔇 HOLD ({holdMethod || direction})
      </span>
    );
  }

  const colors: Record<string, string> = {
    sendrecv: '#3FB950',
    sendonly: '#D29922',
    recvonly: '#D29922',
    inactive: '#F85149',
  };
  const color = colors[direction] || '#8B949E';

  return <span className="font-mono" style={{ color }}>{direction}</span>;
}
