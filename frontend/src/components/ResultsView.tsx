import { useState } from 'react';
import { Search, ArrowLeft, Clock, MessageSquare, AlertTriangle, Activity, Cpu } from 'lucide-react';
import type { AnalysisResult } from '../types/analysis.types';
import CallTimelineView from './CallTimelineView';
import LadderDiagram from './LadderDiagram';
import ErrorPanel from './ErrorPanel';
import SDPComparison from './SDPComparison';
import RCAPanel from './RCAPanel';

interface ResultsViewProps {
  result: AnalysisResult;
  onNewAnalysis: () => void;
}

type Tab = 'overview' | 'ladder' | 'errors' | 'sdp' | 'rca';

const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: 'overview', label: 'Overview', icon: <Activity size={16} /> },
  { id: 'ladder', label: 'Ladder', icon: <MessageSquare size={16} /> },
  { id: 'errors', label: 'Errors', icon: <AlertTriangle size={16} /> },
  { id: 'sdp', label: 'SDP', icon: <Activity size={16} /> },
  { id: 'rca', label: 'RCA', icon: <Search size={16} /> },
];

export default function ResultsView({ result, onNewAnalysis }: ResultsViewProps) {
  const [activeTab, setActiveTab] = useState<Tab>('overview');

  const errorCount = result.detected_errors.length;
  const mismatchCount = result.sdp_pairs.reduce((s, p) => s + p.mismatches.length, 0);
  const sdpPairCount = result.sdp_pairs.length;
  const platform = result.detected_platform && result.detected_platform !== 'GENERIC' ? result.detected_platform : null;

  return (
    <div className="min-h-screen bg-[#0D1117]">
      {/* Top Bar */}
      <header className="border-b border-[#30363D] bg-[#161B22]/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={onNewAnalysis}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm text-[#8B949E] hover:text-[#E6EDF3] hover:bg-[#21262D] transition-colors cursor-pointer"
            >
              <ArrowLeft size={16} />
              New Analysis
            </button>
            <div className="h-5 w-px bg-[#30363D]" />
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#58A6FF] to-[#BC8CFF] flex items-center justify-center">
                <Search size={14} className="text-white" />
              </div>
              <span className="text-sm font-semibold text-[#E6EDF3]">SIP Sherlock</span>
            </div>
          </div>

          {/* Stats pills */}
          <div className="flex items-center gap-3">
            <StatPill icon={<MessageSquare size={12} />} label="Messages" value={result.parsed_message_count} color="#58A6FF" />
            <StatPill icon={<AlertTriangle size={12} />} label="Errors" value={errorCount} color={errorCount > 0 ? '#F85149' : '#3FB950'} />
            {platform && <StatPill icon={<Cpu size={12} />} label="Platform" value={platform} color="#BC8CFF" />}
            <StatPill icon={<Clock size={12} />} label="Time" value={`${result.processing_time_ms}ms`} color="#8B949E" />
          </div>
        </div>
      </header>

      {/* Tab Navigation */}
      <div className="border-b border-[#30363D] bg-[#0D1117]">
        <div className="max-w-7xl mx-auto px-6 flex gap-0">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-5 py-3 text-sm font-medium border-b-2 transition-all cursor-pointer ${
                activeTab === tab.id
                  ? 'border-[#58A6FF] text-[#E6EDF3]'
                  : 'border-transparent text-[#8B949E] hover:text-[#E6EDF3] hover:border-[#30363D]'
              }`}
            >
              {tab.icon}
              {tab.label}
              {tab.id === 'errors' && errorCount > 0 && (
                <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-[#F85149]/20 text-[#F85149]">
                  {errorCount}
                </span>
              )}
              {tab.id === 'sdp' && sdpPairCount > 0 && (
                <span className={`px-1.5 py-0.5 rounded-full text-[10px] font-bold ${
                  mismatchCount > 0
                    ? 'bg-[#D29922]/20 text-[#D29922]'
                    : 'bg-[#58A6FF]/20 text-[#58A6FF]'
                }`}>
                  {sdpPairCount}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <main className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {activeTab === 'overview' && (
          <>
            <CallTimelineView timeline={result.call_timeline} />
            <LadderDiagram data={result.ladder_data} />
            {errorCount > 0 && <ErrorPanel errors={result.detected_errors} />}
            <RCAPanel rca={result.rca} />
          </>
        )}
        {activeTab === 'ladder' && <LadderDiagram data={result.ladder_data} />}
        {activeTab === 'errors' && <ErrorPanel errors={result.detected_errors} />}
        {activeTab === 'sdp' && <SDPComparison pairs={result.sdp_pairs} />}
        {activeTab === 'rca' && <RCAPanel rca={result.rca} />}
      </main>
    </div>
  );
}

function StatPill({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: number | string; color: string }) {
  return (
    <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0D1117] border border-[#30363D]">
      <span style={{ color }}>{icon}</span>
      <span className="text-xs text-[#8B949E]">{label}</span>
      <span className="text-xs font-semibold" style={{ color }}>{value}</span>
    </div>
  );
}
