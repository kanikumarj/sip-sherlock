import { useState, useCallback } from 'react';
import { Search, Activity, Shield } from 'lucide-react';
import AnalysisInput from './components/AnalysisInput';
import ResultsView from './components/ResultsView';
import LoadingScreen from './components/LoadingScreen';
import { analyzeText, analyzeFile, getSample } from './services/api';
import type { AnalysisResult } from './types/analysis.types';

type AppView = 'home' | 'loading' | 'results';

export default function App() {
  const [view, setView] = useState<AppView>('home');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyzeText = useCallback(async (text: string) => {
    setView('loading');
    setError(null);
    try {
      const data = await analyzeText(text);
      setResult(data);
      setView('results');
    } catch (err: any) {
      setError(err.message || 'Analysis failed');
      setView('home');
    }
  }, []);

  const handleAnalyzeFile = useCallback(async (file: File) => {
    setView('loading');
    setError(null);
    try {
      const data = await analyzeFile(file);
      setResult(data);
      setView('results');
    } catch (err: any) {
      setError(err.message || 'File analysis failed');
      setView('home');
    }
  }, []);

  const handleLoadSample = useCallback(async (sampleId: string) => {
    setView('loading');
    setError(null);
    try {
      const sipText = await getSample(sampleId);
      const data = await analyzeText(sipText);
      setResult(data);
      setView('results');
    } catch (err: any) {
      setError(err.message || 'Failed to load sample');
      setView('home');
    }
  }, []);

  const handleNewAnalysis = useCallback(() => {
    setView('home');
    setResult(null);
    setError(null);
  }, []);

  if (view === 'loading') {
    return <LoadingScreen />;
  }

  if (view === 'results' && result) {
    return <ResultsView result={result} onNewAnalysis={handleNewAnalysis} />;
  }

  return (
    <div className="min-h-screen bg-[#0D1117] flex flex-col">
      {/* Header */}
      <header className="border-b border-[#30363D] bg-[#161B22]/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#58A6FF] to-[#BC8CFF] flex items-center justify-center shadow-lg shadow-[#58A6FF]/20">
              <Search size={20} className="text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-[#E6EDF3] tracking-tight">SIP Sherlock</h1>
              <p className="text-xs text-[#8B949E] font-medium">SIP Log Analyzer</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#0D1117] border border-[#30363D]">
              <Activity size={14} className="text-[#3FB950]" />
              <span className="text-xs text-[#8B949E]">Phase 1 — Core Engine</span>
            </div>
          </div>
        </div>
      </header>

      {/* Hero */}
      <main className="flex-1 flex flex-col items-center justify-center px-6 py-12">
        <div className="text-center mb-12 animate-fade-in">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#161B22] border border-[#30363D] mb-6">
            <Shield size={14} className="text-[#BC8CFF]" />
            <span className="text-xs text-[#8B949E] font-medium">AI-Powered SIP Analysis Engine</span>
          </div>
          <h2 className="text-4xl sm:text-5xl font-bold text-[#E6EDF3] mb-4 tracking-tight">
            Decode SIP failures
            <br />
            <span className="bg-gradient-to-r from-[#58A6FF] via-[#BC8CFF] to-[#39D2C0] bg-clip-text text-transparent">
              in seconds
            </span>
          </h2>
          <p className="text-[#8B949E] text-lg max-w-2xl mx-auto leading-relaxed">
            Paste a SIP trace or upload a PCAP — get an interactive ladder diagram,
            SDP mismatch analysis, and AI root cause in one click.
          </p>
        </div>

        {/* Error Toast */}
        {error && (
          <div className="w-full max-w-4xl mb-6 animate-fade-in">
            <div className="bg-[#F85149]/10 border border-[#F85149]/30 rounded-lg px-4 py-3 flex items-center justify-between">
              <span className="text-[#F85149] text-sm whitespace-pre-wrap">{error}</span>
              <button
                onClick={() => setError(null)}
                className="text-[#F85149] hover:text-white text-sm font-medium cursor-pointer"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}

        <AnalysisInput
          onAnalyzeText={handleAnalyzeText}
          onAnalyzeFile={handleAnalyzeFile}
          onLoadSample={handleLoadSample}
          isLoading={false}
        />

        {/* Feature Pills */}
        <div className="mt-16 flex flex-wrap justify-center gap-3 animate-fade-in" style={{ animationDelay: '0.2s' }}>
          {[
            { icon: '🔍', label: 'SIP Parsing' },
            { icon: '📊', label: 'Ladder Diagrams' },
            { icon: '🎯', label: 'Error Detection' },
            { icon: '📡', label: 'SDP Analysis' },
            { icon: '🤖', label: 'AI Root Cause' },
            { icon: '📋', label: 'PDF Export' },
          ].map((f) => (
            <span
              key={f.label}
              className="px-4 py-2 rounded-full bg-[#161B22] border border-[#30363D] text-sm text-[#8B949E]
                         hover:border-[#58A6FF]/50 hover:text-[#E6EDF3] transition-all duration-200"
            >
              {f.icon} {f.label}
            </span>
          ))}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#30363D] py-4 px-6 text-center">
        <p className="text-xs text-[#656D76]">
          SIP Sherlock v1.0 — Built for VoIP engineers who debug at 2AM
        </p>
      </footer>
    </div>
  );
}
