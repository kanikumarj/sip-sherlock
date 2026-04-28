import { AlertTriangle, AlertCircle, Info, XOctagon } from 'lucide-react';
import type { SIPError } from '../types/analysis.types';

interface ErrorPanelProps {
  errors: SIPError[];
}

const SEVERITY_CONFIG: Record<string, { color: string; bgColor: string; icon: React.ReactNode; label: string }> = {
  CRITICAL: {
    color: '#F85149',
    bgColor: '#F8514915',
    icon: <XOctagon size={16} />,
    label: 'Critical',
  },
  HIGH: {
    color: '#F85149',
    bgColor: '#F8514910',
    icon: <AlertCircle size={16} />,
    label: 'High',
  },
  MEDIUM: {
    color: '#D29922',
    bgColor: '#D2992210',
    icon: <AlertTriangle size={16} />,
    label: 'Medium',
  },
  LOW: {
    color: '#8B949E',
    bgColor: '#8B949E10',
    icon: <Info size={16} />,
    label: 'Low',
  },
};

export default function ErrorPanel({ errors }: ErrorPanelProps) {
  if (errors.length === 0) {
    return (
      <div className="bg-[#161B22] border border-[#30363D] rounded-xl p-6 animate-fade-in">
        <h3 className="text-lg font-semibold text-[#E6EDF3] mb-4 flex items-center gap-2">
          <AlertTriangle size={18} className="text-[#3FB950]" />
          Detected Errors
        </h3>
        <div className="flex items-center gap-3 p-4 rounded-lg bg-[#3FB950]/10 border border-[#3FB950]/20">
          <span className="text-xl">✅</span>
          <p className="text-[#3FB950] text-sm font-medium">No protocol errors detected in this trace</p>
        </div>
      </div>
    );
  }

  const criticalCount = errors.filter((e) => e.severity === 'CRITICAL' || e.severity === 'HIGH').length;
  const warningCount = errors.filter((e) => e.severity === 'MEDIUM').length;

  return (
    <div className="bg-[#161B22] border border-[#30363D] rounded-xl p-6 animate-fade-in">
      <div className="flex items-center justify-between mb-5">
        <h3 className="text-lg font-semibold text-[#E6EDF3] flex items-center gap-2">
          <AlertTriangle size={18} className="text-[#F85149]" />
          Detected Errors
          <span className="text-xs text-[#8B949E] font-normal ml-2">{errors.length} issues found</span>
        </h3>
        <div className="flex items-center gap-2">
          {criticalCount > 0 && (
            <span className="px-2 py-0.5 rounded text-xs font-medium bg-[#F85149]/15 text-[#F85149] border border-[#F85149]/20">
              {criticalCount} Critical/High
            </span>
          )}
          {warningCount > 0 && (
            <span className="px-2 py-0.5 rounded text-xs font-medium bg-[#D29922]/15 text-[#D29922] border border-[#D29922]/20">
              {warningCount} Warning
            </span>
          )}
        </div>
      </div>

      <div className="space-y-3">
        {errors.map((err, i) => {
          const cfg = SEVERITY_CONFIG[err.severity] || SEVERITY_CONFIG.LOW;
          return (
            <div
              key={i}
              className="rounded-lg p-4 border transition-all duration-200 hover:border-opacity-60"
              style={{ backgroundColor: cfg.bgColor, borderColor: `${cfg.color}25` }}
            >
              <div className="flex items-start gap-3">
                <div className="mt-0.5 flex-shrink-0" style={{ color: cfg.color }}>
                  {cfg.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="text-sm font-semibold" style={{ color: cfg.color }}>
                      {err.error_type}
                    </span>
                    {err.error_code && (
                      <span
                        className="px-1.5 py-0.5 rounded text-xs font-mono font-medium"
                        style={{ backgroundColor: `${cfg.color}20`, color: cfg.color }}
                      >
                        {err.error_code}
                      </span>
                    )}
                    <span
                      className="px-1.5 py-0.5 rounded text-xs font-medium"
                      style={{ backgroundColor: `${cfg.color}15`, color: cfg.color }}
                    >
                      {cfg.label}
                    </span>
                    <span className="text-xs text-[#656D76]">
                      msg #{err.message_index}
                    </span>
                  </div>
                  <p className="text-sm text-[#E6EDF3] mb-2">{err.description}</p>
                  <p className="text-xs text-[#8B949E] leading-relaxed">
                    💡 {err.engineer_explanation}
                  </p>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
