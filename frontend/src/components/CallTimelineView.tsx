import { Phone, PhoneOff, PhoneIncoming, Clock, AlertTriangle, CheckCircle, XCircle, Globe, Server } from 'lucide-react';
import type { CallTimeline } from '../types/analysis.types';

interface CallTimelineViewProps {
  timeline: CallTimeline;
}

const DISPOSITION_CONFIG: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
  ANSWERED: { color: '#3FB950', icon: <CheckCircle size={18} />, label: 'Answered' },
  FAILED: { color: '#F85149', icon: <XCircle size={18} />, label: 'Failed' },
  BUSY: { color: '#D29922', icon: <PhoneOff size={18} />, label: 'Busy' },
  CANCELLED: { color: '#8B949E', icon: <PhoneOff size={18} />, label: 'Cancelled' },
  UNAVAILABLE: { color: '#F85149', icon: <XCircle size={18} />, label: 'Unavailable' },
  NOT_FOUND: { color: '#F85149', icon: <XCircle size={18} />, label: 'Not Found' },
  REJECTED: { color: '#F85149', icon: <XCircle size={18} />, label: 'Rejected' },
  AUTH_REQUIRED: { color: '#D29922', icon: <AlertTriangle size={18} />, label: 'Auth Required' },
  UNKNOWN: { color: '#656D76', icon: <AlertTriangle size={18} />, label: 'Unknown' },
};

function formatDuration(seconds: number | null, estimated: boolean): string {
  if (seconds == null) return '—';
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms${estimated ? ' ~' : ''}`;
  if (seconds < 60) return `${seconds.toFixed(1)}s${estimated ? ' ~' : ''}`;
  const m = Math.floor(seconds / 60);
  const s = (seconds % 60).toFixed(0);
  return `${m}m ${s}s${estimated ? ' ~' : ''}`;
}

export default function CallTimelineView({ timeline }: CallTimelineViewProps) {
  const config = DISPOSITION_CONFIG[timeline.final_disposition] || DISPOSITION_CONFIG.UNKNOWN;

  return (
    <div className="bg-[#161B22] border border-[#30363D] rounded-xl p-6 animate-fade-in">
      <h3 className="text-lg font-semibold text-[#E6EDF3] mb-5 flex items-center gap-2">
        <Phone size={18} className="text-[#58A6FF]" />
        Call Summary
      </h3>

      {/* Disposition Badge */}
      <div className="flex items-center gap-3 mb-6 flex-wrap">
        <div
          className="flex items-center gap-2 px-4 py-2 rounded-lg"
          style={{ backgroundColor: `${config.color}15`, border: `1px solid ${config.color}30` }}
        >
          <span style={{ color: config.color }}>{config.icon}</span>
          <span className="font-semibold text-sm" style={{ color: config.color }}>
            {config.label}
          </span>
        </div>
        {timeline.failure_point && (
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#F85149]/10 border border-[#F85149]/20">
            <AlertTriangle size={14} className="text-[#F85149]" />
            <span className="text-xs text-[#F85149]">{timeline.failure_point}</span>
          </div>
        )}
      </div>

      {/* Info Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <InfoTile
          icon={<PhoneIncoming size={16} className="text-[#3FB950]" />}
          label="From"
          value={timeline.calling_party || '—'}
          subValue={timeline.calling_ip || undefined}
          subIcon={<Server size={10} className="text-[#8B949E]" />}
        />
        <InfoTile
          icon={<Phone size={16} className="text-[#58A6FF]" />}
          label="To"
          value={timeline.called_party || '—'}
          subValue={timeline.called_ip || undefined}
          subIcon={<Globe size={10} className="text-[#8B949E]" />}
        />
        <InfoTile
          icon={<Clock size={16} className="text-[#D29922]" />}
          label="Duration"
          value={formatDuration(timeline.duration_seconds, timeline.duration_estimated)}
          subValue={timeline.duration_estimated ? 'estimated' : undefined}
        />
        <InfoTile
          icon={<Clock size={16} className="text-[#BC8CFF]" />}
          label="Call ID"
          value={timeline.call_id ? (timeline.call_id.length > 20 ? timeline.call_id.substring(0, 18) + '...' : timeline.call_id) : '—'}
          mono
        />
      </div>

      {/* Timeline Bar */}
      {(timeline.call_start || timeline.call_end) && (
        <div className="mt-6 pt-5 border-t border-[#30363D]">
          <div className="flex items-center gap-3">
            {timeline.call_start && (
              <TimePoint label="Start" time={timeline.call_start} color="#3FB950" />
            )}
            <div className="flex-1 h-0.5 bg-gradient-to-r from-[#3FB950] via-[#58A6FF] to-[#F85149] rounded opacity-30" />
            {timeline.call_answered && timeline.call_answer_time && (
              <>
                <TimePoint label="Answer" time={timeline.call_answer_time} color="#58A6FF" />
                <div className="flex-1 h-0.5 bg-gradient-to-r from-[#58A6FF] to-[#F85149] rounded opacity-30" />
              </>
            )}
            {timeline.call_end && (
              <TimePoint label="End" time={timeline.call_end} color="#F85149" />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function InfoTile({ icon, label, value, subValue, subIcon, mono }: {
  icon: React.ReactNode; label: string; value: string;
  subValue?: string; subIcon?: React.ReactNode; mono?: boolean;
}) {
  return (
    <div className="bg-[#0D1117] rounded-lg p-3 border border-[#30363D]/50">
      <div className="flex items-center gap-1.5 mb-1">
        {icon}
        <span className="text-xs text-[#8B949E]">{label}</span>
      </div>
      <p className={`text-sm text-[#E6EDF3] truncate ${mono ? 'font-mono text-xs' : 'font-medium'}`}>
        {value}
      </p>
      {subValue && (
        <div className="flex items-center gap-1 mt-1">
          {subIcon}
          <span className="text-[10px] text-[#8B949E] font-mono">{subValue}</span>
        </div>
      )}
    </div>
  );
}

function TimePoint({ label, time, color }: { label: string; time: string; color: string }) {
  return (
    <div className="text-center flex-shrink-0">
      <div className="w-3 h-3 rounded-full mx-auto mb-1" style={{ backgroundColor: color }} />
      <p className="text-xs font-medium" style={{ color }}>{label}</p>
      <p className="text-[10px] text-[#8B949E] font-mono">{time}</p>
    </div>
  );
}
