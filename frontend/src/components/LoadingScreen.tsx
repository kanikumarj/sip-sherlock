import { useState, useEffect } from 'react';

const STEPS = [
  { label: 'Parsing SIP messages...', icon: '📨' },
  { label: 'Extracting SDP bodies...', icon: '📡' },
  { label: 'Detecting protocol errors...', icon: '🔍' },
  { label: 'Building ladder diagram...', icon: '📊' },
  { label: 'Running AI root cause analysis...', icon: '🤖' },
  { label: 'Compiling results...', icon: '✅' },
];

export default function LoadingScreen() {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setStep((s) => (s < STEPS.length - 1 ? s + 1 : s));
    }, 1800);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#0D1117] flex items-center justify-center">
      <div className="text-center animate-fade-in">
        {/* Animated Rings */}
        <div className="sherlock-loader mx-auto mb-8">
          <div className="ring" />
          <div className="ring" />
          <div className="ring" />
          <div className="icon">🔎</div>
        </div>

        <h2 className="text-2xl font-bold text-[#E6EDF3] mb-2">Analyzing SIP Trace</h2>
        <p className="text-[#8B949E] mb-8">Sherlock is on the case...</p>

        {/* Steps */}
        <div className="space-y-3 max-w-xs mx-auto text-left">
          {STEPS.map((s, i) => (
            <div
              key={i}
              className={`flex items-center gap-3 px-4 py-2 rounded-lg transition-all duration-500 ${
                i < step
                  ? 'bg-[#3FB950]/10 border border-[#3FB950]/20'
                  : i === step
                    ? 'bg-[#58A6FF]/10 border border-[#58A6FF]/20 animate-pulse-glow'
                    : 'bg-[#161B22] border border-transparent opacity-40'
              }`}
            >
              <span className="text-base">{s.icon}</span>
              <span
                className={`text-sm ${
                  i <= step ? 'text-[#E6EDF3]' : 'text-[#656D76]'
                }`}
              >
                {s.label}
              </span>
              {i < step && <span className="ml-auto text-[#3FB950] text-xs">✓</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
