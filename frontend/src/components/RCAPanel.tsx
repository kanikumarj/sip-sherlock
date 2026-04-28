import { Brain, Wrench, AlertTriangle, ChevronRight, Layers, MapPin, TrendingUp } from 'lucide-react';
import type { RCAResult } from '../types/analysis.types';

interface RCAPanelProps {
  rca: RCAResult;
}

const LAYER_COLORS: Record<string, string> = {
  SIGNALING: '#58A6FF',
  MEDIA: '#BC8CFF',
  NETWORK: '#D29922',
  AUTHENTICATION: '#F85149',
  POLICY: '#39D2C0',
  CAPACITY: '#F0883E',
};

export default function RCAPanel({ rca }: RCAPanelProps) {
  const layerColor = LAYER_COLORS[rca.failure_layer] || '#58A6FF';

  return (
    <div className="bg-[#161B22] border border-[#30363D] rounded-xl overflow-hidden animate-fade-in">
      {/* Header with gradient */}
      <div className="px-6 py-5 border-b border-[#30363D] bg-gradient-to-r from-[#161B22] to-[#1C2128]">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-[#E6EDF3] flex items-center gap-2">
            <Brain size={18} className="text-[#BC8CFF]" />
            Root Cause Analysis
          </h3>
          <div className="flex items-center gap-2">
            <span className="px-2 py-1 rounded text-xs font-medium" style={{ backgroundColor: `${layerColor}15`, color: layerColor, border: `1px solid ${layerColor}30` }}>
              <Layers size={10} className="inline mr-1" />
              {rca.failure_layer}
            </span>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Root Cause */}
        <div className="p-4 rounded-lg bg-[#F85149]/5 border border-[#F85149]/15">
          <p className="text-xs text-[#F85149] font-semibold uppercase tracking-wider mb-2">Root Cause</p>
          <p className="text-[#E6EDF3] font-medium text-sm">{rca.root_cause}</p>
          {rca.root_cause_detail && (
            <p className="text-[#8B949E] text-xs mt-2 leading-relaxed">{rca.root_cause_detail}</p>
          )}
        </div>

        {/* Confidence + Location Row */}
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-[#0D1117] rounded-lg p-4 border border-[#30363D]/50">
            <div className="flex items-center gap-1.5 mb-2">
              <TrendingUp size={14} className="text-[#58A6FF]" />
              <span className="text-xs text-[#8B949E]">Confidence</span>
            </div>
            <div className="confidence-bar">
              <div className="confidence-fill" style={{
                width: `${rca.confidence}%`,
                backgroundColor: rca.confidence >= 80 ? '#3FB950' : rca.confidence >= 50 ? '#D29922' : '#F85149'
              }} />
            </div>
            <p className="text-right text-xs mt-1 font-medium" style={{
              color: rca.confidence >= 80 ? '#3FB950' : rca.confidence >= 50 ? '#D29922' : '#F85149'
            }}>{rca.confidence}%</p>
          </div>
          <div className="bg-[#0D1117] rounded-lg p-4 border border-[#30363D]/50">
            <div className="flex items-center gap-1.5 mb-2">
              <MapPin size={14} className="text-[#D29922]" />
              <span className="text-xs text-[#8B949E]">Failure Location</span>
            </div>
            <p className="text-sm text-[#E6EDF3] font-medium">{rca.failure_location || '—'}</p>
          </div>
        </div>

        {/* Contributing Factors */}
        {rca.contributing_factors.length > 0 && (
          <div>
            <p className="text-xs text-[#8B949E] font-semibold uppercase tracking-wider mb-3">Contributing Factors</p>
            <div className="space-y-1.5">
              {rca.contributing_factors.map((f, i) => (
                <div key={i} className="flex items-start gap-2 text-sm text-[#E6EDF3]">
                  <ChevronRight size={14} className="text-[#58A6FF] mt-0.5 flex-shrink-0" />
                  <span>{f}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommended Fixes */}
        {rca.recommended_fixes.length > 0 && (
          <div>
            <p className="text-xs text-[#8B949E] font-semibold uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <Wrench size={12} />
              Recommended Fixes
            </p>
            <div className="space-y-2">
              {rca.recommended_fixes.map((fix, i) => (
                <div key={i} className="bg-[#0D1117] rounded-lg p-3 border border-[#30363D]/50 flex items-start gap-3">
                  <span className="w-6 h-6 rounded-full bg-[#58A6FF]/15 text-[#58A6FF] flex items-center justify-center text-xs font-bold flex-shrink-0">
                    {fix.priority}
                  </span>
                  <div className="flex-1">
                    <p className="text-sm text-[#E6EDF3] font-medium">{fix.action}</p>
                    <p className="text-xs text-[#8B949E] mt-0.5">{fix.detail}</p>
                    <span className="inline-block mt-1 px-1.5 py-0.5 rounded text-[10px] font-mono text-[#8B949E] bg-[#21262D]">
                      {fix.platform}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Config Snippet */}
        {rca.config_snippet && (
          <div>
            <p className="text-xs text-[#8B949E] font-semibold uppercase tracking-wider mb-2">Config Suggestion</p>
            <pre className="sip-raw-message text-xs">{rca.config_snippet}</pre>
          </div>
        )}

        {/* Escalation Warning */}
        {rca.escalation_needed && (
          <div className="p-3 rounded-lg bg-[#D29922]/10 border border-[#D29922]/20 flex items-start gap-2">
            <AlertTriangle size={16} className="text-[#D29922] mt-0.5" />
            <div>
              <p className="text-sm text-[#D29922] font-medium">Escalation Recommended</p>
              {rca.escalation_reason && <p className="text-xs text-[#8B949E] mt-0.5">{rca.escalation_reason}</p>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
