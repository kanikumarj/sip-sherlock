import { useState, useCallback, useRef } from 'react';
import { Upload, FileText, ClipboardPaste, Zap, ChevronRight } from 'lucide-react';

interface AnalysisInputProps {
  onAnalyzeText: (text: string) => void;
  onAnalyzeFile: (file: File) => void;
  onLoadSample: (sampleId: string) => void;
  isLoading: boolean;
}

const SAMPLES = [
  { id: 'cucm_488', label: 'CUBE 488 Codec Mismatch', desc: 'G.729 rejected by carrier — needs G.711', color: '#F85149' },
  { id: 'teams_drop', label: '503 Carrier Trunk Down', desc: 'SIP trunk unavailable — immediate reject', color: '#D29922' },
  { id: 'sbc_timeout', label: 'Registration Auth Failure', desc: '401→403 credentials rejected', color: '#BC8CFF' },
  { id: 'srtp_mismatch', label: 'SRTP/RTP Mismatch', desc: 'Encryption mismatch — one-way audio risk', color: '#39D2C0' },
  { id: 'busy_486', label: '486 Busy Here', desc: 'Called party on another call', color: '#F0883E' },
  { id: 'unavailable_480', label: '480 Unavailable', desc: 'Endpoint not registered or DND', color: '#F85149' },
  { id: 'server_error_500', label: '500 Server Error', desc: 'Internal server processing failure', color: '#DA3633' },
  { id: 'address_incomplete_484', label: '484 Address Incomplete', desc: 'Number needs more digits or prefix', color: '#D29922' },
  { id: 'success', label: 'Successful Call', desc: 'Clean INVITE→200→BYE flow with G.711', color: '#3FB950' },
];

export default function AnalysisInput({ onAnalyzeText, onAnalyzeFile, onLoadSample, isLoading }: AnalysisInputProps) {
  const [activeTab, setActiveTab] = useState<'paste' | 'upload'>('paste');
  const [sipText, setSipText] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSubmit = useCallback(() => {
    if (activeTab === 'paste' && sipText.trim()) {
      onAnalyzeText(sipText);
    } else if (activeTab === 'upload' && selectedFile) {
      onAnalyzeFile(selectedFile);
    }
  }, [activeTab, sipText, selectedFile, onAnalyzeText, onAnalyzeFile]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) {
      setSelectedFile(file);
      setActiveTab('upload');
    }
  }, []);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) setSelectedFile(file);
  }, []);

  const canSubmit = (activeTab === 'paste' && sipText.trim().length > 0) ||
    (activeTab === 'upload' && selectedFile !== null);

  return (
    <div className="w-full max-w-4xl mx-auto animate-fade-in">
      {/* Tab Switcher */}
      <div className="flex rounded-t-xl overflow-hidden border border-[#30363D] border-b-0">
        <button
          onClick={() => setActiveTab('paste')}
          className={`flex-1 flex items-center justify-center gap-2 px-6 py-4 text-sm font-medium transition-all duration-200 cursor-pointer ${
            activeTab === 'paste'
              ? 'bg-[#161B22] text-[#58A6FF] border-b-2 border-[#58A6FF]'
              : 'bg-[#0D1117] text-[#8B949E] hover:text-[#E6EDF3] hover:bg-[#161B22]/50'
          }`}
        >
          <ClipboardPaste size={18} />
          Paste SIP Log
        </button>
        <button
          onClick={() => setActiveTab('upload')}
          className={`flex-1 flex items-center justify-center gap-2 px-6 py-4 text-sm font-medium transition-all duration-200 cursor-pointer ${
            activeTab === 'upload'
              ? 'bg-[#161B22] text-[#58A6FF] border-b-2 border-[#58A6FF]'
              : 'bg-[#0D1117] text-[#8B949E] hover:text-[#E6EDF3] hover:bg-[#161B22]/50'
          }`}
        >
          <Upload size={18} />
          Upload File
        </button>
      </div>

      {/* Input Area */}
      <div className="bg-[#161B22] border border-[#30363D] border-t-0 rounded-b-xl p-6">
        {activeTab === 'paste' ? (
          <textarea
            value={sipText}
            onChange={(e) => setSipText(e.target.value)}
            placeholder="Paste raw SIP trace, CUCM log, or CUBE debug output here..."
            className="w-full h-72 bg-[#0D1117] text-[#E6EDF3] border border-[#30363D] rounded-lg p-4
                       font-mono text-sm resize-none focus:outline-none focus:border-[#58A6FF]
                       placeholder:text-[#656D76] transition-colors duration-200"
            spellCheck={false}
          />
        ) : (
          <div
            onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`w-full h-72 border-2 border-dashed rounded-lg flex flex-col items-center justify-center gap-4 cursor-pointer transition-all duration-200 ${
              isDragOver
                ? 'border-[#58A6FF] bg-[#58A6FF]/5'
                : selectedFile
                  ? 'border-[#3FB950] bg-[#3FB950]/5'
                  : 'border-[#30363D] hover:border-[#58A6FF]/50 hover:bg-[#0D1117]'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".log,.txt,.pcap,.pcapng"
              onChange={handleFileSelect}
              className="hidden"
            />
            {selectedFile ? (
              <>
                <FileText size={48} className="text-[#3FB950]" />
                <div className="text-center">
                  <p className="text-[#E6EDF3] font-medium">{selectedFile.name}</p>
                  <p className="text-[#8B949E] text-sm mt-1">
                    {(selectedFile.size / 1024).toFixed(1)} KB
                  </p>
                </div>
              </>
            ) : (
              <>
                <Upload size={48} className="text-[#8B949E]" />
                <div className="text-center">
                  <p className="text-[#E6EDF3]">Drag & drop or click to upload</p>
                  <p className="text-[#8B949E] text-sm mt-1">
                    Accepts .log .txt .pcap .pcapng — Max 10MB
                  </p>
                </div>
              </>
            )}
          </div>
        )}

        {/* Analyze Button */}
        <button
          onClick={handleSubmit}
          disabled={!canSubmit || isLoading}
          className={`w-full mt-6 py-4 rounded-lg font-semibold text-base flex items-center justify-center gap-2 transition-all duration-200 cursor-pointer ${
            canSubmit && !isLoading
              ? 'bg-[#1F6FEB] hover:bg-[#58A6FF] text-white shadow-lg shadow-[#1F6FEB]/20 hover:shadow-[#58A6FF]/30'
              : 'bg-[#21262D] text-[#656D76] cursor-not-allowed'
          }`}
        >
          <Zap size={20} />
          {isLoading ? 'Analyzing...' : 'Analyze SIP Trace'}
        </button>
      </div>

      {/* Sample Traces */}
      <div className="mt-8">
        <p className="text-[#8B949E] text-sm mb-4 text-center">
          Or try a sample trace:
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {SAMPLES.map((sample) => (
            <button
              key={sample.id}
              onClick={() => onLoadSample(sample.id)}
              disabled={isLoading}
              className="group bg-[#161B22] border border-[#30363D] rounded-lg p-4 text-left
                         hover:border-[#58A6FF]/50 hover:bg-[#1C2128] transition-all duration-200 cursor-pointer"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: sample.color }}
                  />
                  <span className="text-[#E6EDF3] text-sm font-medium">
                    {sample.label}
                  </span>
                </div>
                <ChevronRight size={14} className="text-[#656D76] group-hover:text-[#58A6FF] transition-colors" />
              </div>
              <p className="text-[#8B949E] text-xs mt-2">{sample.desc}</p>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
