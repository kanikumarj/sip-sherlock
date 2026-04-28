/**
 * ═══════════════════════════════════════════════════════════════
 * SIP Sherlock — NEURAL SIGNAL ARCHITECTURE — Ladder Diagram v3.0
 * ═══════════════════════════════════════════════════════════════
 */
import { useState, useRef, useMemo, useEffect, useCallback } from 'react';
import {
  X, ChevronDown, ChevronUp, Signal, Play, Pause, SkipBack, SkipForward,
  ZoomIn, ZoomOut, Maximize2, Search, Copy, Check, Radio, Zap,
  Phone, Server, Globe, Shield, Cpu, Wifi, Monitor, AudioLines,
} from 'lucide-react';
import type { LadderData, LadderMessage } from '../types/analysis.types';

// ─── Types ─────────────────────────────────────────────────────
type Theme = 'neural' | 'matrix' | 'blueprint';
type DeviceType = 'cucm' | 'cube' | 'sbc' | 'phone' | 'carrier' | 'teams' | 'genesys' | 'audiocodes' | 'generic';

interface LadderDiagramProps { data: LadderData; }

// ─── Constants ─────────────────────────────────────────────────
const COL_W = 200;
const ROW_H = 64;
const HDR_H = 100;
const TS_W = 90;
const PAD_B = 40;

const DEVICE_COLORS: Record<DeviceType, string> = {
  cucm: '#6366f1', cube: '#0ea5e9', sbc: '#8b5cf6', phone: '#10b981',
  carrier: '#f59e0b', teams: '#3b82f6', genesys: '#ec4899', audiocodes: '#14b8a6', generic: '#64748b',
};

const DEVICE_LABELS: Record<DeviceType, string> = {
  cucm: 'Call Manager', cube: 'Voice Gateway', sbc: 'Session Border Ctrl',
  phone: 'Endpoint', carrier: 'Carrier Trunk', teams: 'Teams DR',
  genesys: 'Contact Center', audiocodes: 'Media Gateway', generic: 'SIP Device',
};

const DEVICE_ICONS: Record<DeviceType, React.ReactNode> = {
  cucm: <Cpu size={16}/>, cube: <Wifi size={16}/>, sbc: <Shield size={16}/>,
  phone: <Phone size={16}/>, carrier: <Globe size={16}/>, teams: <Monitor size={16}/>,
  genesys: <AudioLines size={16}/>, audiocodes: <Server size={16}/>, generic: <Radio size={16}/>,
};

const SEV_COLORS: Record<string, string> = {
  normal: '#58A6FF', warning: '#D29922', error: '#F85149', critical: '#F85149',
};

const THEME_BG: Record<Theme, string> = {
  neural: '#030712', matrix: '#000000', blueprint: '#0a1628',
};

const SPEEDS = [0.5, 1, 2, 5];

// ─── Helpers ───────────────────────────────────────────────────
function detectDevice(name: string): DeviceType {
  const n = name.toLowerCase();
  if (n.includes('cucm') || n.includes('callmanager')) return 'cucm';
  if (n.includes('cube')) return 'cube';
  if (n.includes('sbc') || n.includes('audiocodes')) return 'sbc';
  if (n.includes('phone') || n.includes('ip phone')) return 'phone';
  if (n.includes('carrier') || n.includes('att') || n.includes('at&t') || n.includes('verizon') || n.includes('trunk')) return 'carrier';
  if (n.includes('teams') || n.includes('microsoft')) return 'teams';
  if (n.includes('genesys')) return 'genesys';
  if (/^\d+\.\d+\.\d+\.\d+/.test(n)) return 'phone';
  if (/^\[/.test(n)) return 'phone';
  return 'generic';
}

function getArrowColor(msg: LadderMessage, theme: Theme): string {
  if (theme === 'matrix') return msg.severity === 'error' || msg.severity === 'critical' ? '#ff3333' : '#00ff41';
  if (theme === 'blueprint') return msg.severity === 'error' || msg.severity === 'critical' ? '#ef4444' : '#67e8f9';
  return SEV_COLORS[msg.severity] || '#58A6FF';
}

function getDash(msg: LadderMessage): string {
  if (msg.type === 'retransmission') return '4,4';
  if (msg.type === 'response') return '8,4';
  return '';
}

function parseSipLine(line: string): React.ReactNode {
  const trimmed = line.trimStart();
  // SDP
  if (/^[a-z]=/i.test(trimmed)) {
    return <><span className="sip-sdp-key">{trimmed.substring(0, 2)}</span><span className="sip-sdp-line">{trimmed.substring(2)}</span></>;
  }
  // Request line
  if (/^(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|PRACK|UPDATE|REFER|SUBSCRIBE|NOTIFY|INFO|MESSAGE|PUBLISH)\s/i.test(trimmed)) {
    return <span className="sip-method">{trimmed}</span>;
  }
  // Response line
  if (/^SIP\/2\.0\s+(\d{3})/.test(trimmed)) {
    const code = parseInt(trimmed.match(/(\d{3})/)![1]);
    const cls = code >= 500 ? 'sip-status-5xx' : code >= 400 ? 'sip-status-4xx' : code >= 200 ? 'sip-status-2xx' : 'sip-status-1xx';
    return <span className={cls}>{trimmed}</span>;
  }
  // Headers
  const hMatch = trimmed.match(/^([A-Za-z-]+)\s*:\s*(.*)/);
  if (hMatch) {
    const hName = hMatch[1].toLowerCase();
    let cls = 'sip-header-content';
    if (['via', 'route', 'record-route', 'contact', 'max-forwards'].includes(hName)) cls = 'sip-header-routing';
    else if (['from', 'to', 'p-asserted-identity', 'remote-party-id', 'diversion'].includes(hName)) cls = 'sip-header-identity';
    else if (['call-id', 'cseq', 'user-agent', 'server', 'allow', 'supported'].includes(hName)) cls = 'sip-header-session';
    return <><span className={cls}>{hMatch[1]}:</span><span className="sip-header-value"> {hMatch[2]}</span></>;
  }
  return <span className="sip-header-value">{line}</span>;
}

// ═══════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════
export default function LadderDiagram({ data }: LadderDiagramProps) {
  const { participants, messages } = data;
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem('ladder-theme') as Theme) || 'neural');
  const [selected, setSelected] = useState<LadderMessage | null>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [zoom, setZoom] = useState(100);
  const [playIdx, setPlayIdx] = useState(-1);
  const [isPlaying, setIsPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [copied, setCopied] = useState(false);
  const [hoverIdx, setHoverIdx] = useState(-1);
  const viewRef = useRef<HTMLDivElement>(null);
  const playTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => { localStorage.setItem('ladder-theme', theme); }, [theme]);

  // Playback engine
  useEffect(() => {
    if (!isPlaying) return;
    if (playIdx >= messages.length - 1) { setIsPlaying(false); return; }
    const delay = Math.max(120, 600 / speed);
    playTimer.current = setTimeout(() => setPlayIdx(p => p + 1), delay);
    return () => clearTimeout(playTimer.current);
  }, [isPlaying, playIdx, speed, messages.length]);

  const togglePlay = useCallback(() => {
    if (playIdx >= messages.length - 1) setPlayIdx(-1);
    setIsPlaying(p => !p);
  }, [playIdx, messages.length]);

  const stepPrev = useCallback(() => { setIsPlaying(false); setPlayIdx(p => Math.max(-1, p - 1)); }, []);
  const stepNext = useCallback(() => { setIsPlaying(false); setPlayIdx(p => Math.min(messages.length - 1, p + 1)); }, [messages.length]);
  const cycleSpeed = useCallback(() => setSpeed(s => SPEEDS[(SPEEDS.indexOf(s) + 1) % SPEEDS.length]), []);
  const cycleTheme = useCallback(() => {
    const ts: Theme[] = ['neural', 'matrix', 'blueprint'];
    setTheme(t => ts[(ts.indexOf(t) + 1) % ts.length]);
  }, []);
  const zoomIn = useCallback(() => setZoom(z => Math.min(200, z + 25)), []);
  const zoomOut = useCallback(() => setZoom(z => Math.max(50, z - 25)), []);
  const zoomFit = useCallback(() => setZoom(100), []);

  const copyRaw = useCallback(() => {
    if (!selected) return;
    navigator.clipboard.writeText(selected.raw_message);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [selected]);

  // Failure index
  const failIdx = useMemo(() => messages.findIndex(m => m.severity === 'critical' || m.severity === 'error'), [messages]);

  // Device types
  const deviceTypes = useMemo(() => participants.map(detectDevice), [participants]);

  // Dimensions
  const totalW = TS_W + participants.length * COL_W + 40;
  const totalH = HDR_H + messages.length * ROW_H + PAD_B;
  const getColX = (p: string) => TS_W + participants.indexOf(p) * COL_W + COL_W / 2;
  const getRowY = (i: number) => HDR_H + i * ROW_H + ROW_H / 2;

  if (!participants.length) {
    return (
      <div className="bg-[#161B22] border border-[#30363D] rounded-xl p-8 text-center">
        <Signal size={32} className="text-[#656D76] mx-auto mb-3" />
        <p className="text-[#8B949E]">No ladder diagram data available</p>
      </div>
    );
  }

  const themeClass = theme === 'matrix' ? 'theme-matrix' : theme === 'blueprint' ? 'theme-blueprint' : '';
  const bg = THEME_BG[theme];

  return (
    <div className={`rounded-xl overflow-hidden border border-[rgba(255,255,255,0.06)] animate-fade-in ${themeClass}`} style={{ background: bg }}>
      {/* ─── Controls Bar ─── */}
      <div className="nsa-controls">
        <button onClick={() => setCollapsed(c => !c)} className="nsa-ctrl-btn" title="Toggle">
          <Signal size={13}/>
          <span className="font-semibold text-[#E6EDF3]">Ladder</span>
          <span style={{color:'#656D76',marginLeft:2}}>{messages.length} msgs · {participants.length} nodes</span>
          {collapsed ? <ChevronDown size={13}/> : <ChevronUp size={13}/>}
        </button>
        <div style={{flex:1}}/>
        <button onClick={cycleTheme} className="nsa-ctrl-btn" title="Theme">
          {theme === 'neural' ? '🔮' : theme === 'matrix' ? '🟢' : '📐'} {theme.charAt(0).toUpperCase() + theme.slice(1)}
        </button>
        <button onClick={zoomOut} className="nsa-ctrl-btn" title="Zoom Out"><ZoomOut size={13}/></button>
        <span style={{fontSize:11,color:'#8B949E',minWidth:32,textAlign:'center'}}>{zoom}%</span>
        <button onClick={zoomIn} className="nsa-ctrl-btn" title="Zoom In"><ZoomIn size={13}/></button>
        <button onClick={zoomFit} className="nsa-ctrl-btn" title="Fit"><Maximize2 size={13}/></button>
      </div>

      {/* ─── Diagram Body ─── */}
      {!collapsed && (
        <>
          <div ref={viewRef} style={{ overflow:'auto', maxHeight: 650, position:'relative', background: bg }}>
            {/* Ambient BG + Grid */}
            <div className="nsa-ambient"/>
            <div className="nsa-grid"/>

            <div style={{ position:'relative', width: totalW * zoom / 100, height: totalH * zoom / 100, transform: `scale(${zoom/100})`, transformOrigin:'top left', minWidth: totalW }}>
              {/* ─── Participant Headers ─── */}
              {participants.map((p, i) => {
                const dt = deviceTypes[i];
                const color = DEVICE_COLORS[dt];
                const cx = getColX(p);
                return (
                  <div key={p}>
                    {/* Timeline Spine */}
                    <div className="nsa-spine" style={{ left: cx, top: HDR_H, bottom: PAD_B, borderLeft:`1px dashed ${color}30`, '--spine-color': `${color}50` } as React.CSSProperties}/>

                    {/* Device Card */}
                    <div className="nsa-device-card" style={{ position:'absolute', left: cx - 80, top: 12, width: 160, '--device-color': color } as React.CSSProperties}>
                      <div style={{display:'flex',alignItems:'center',justifyContent:'center',gap:6,marginBottom:4}}>
                        <span style={{color}}>{DEVICE_ICONS[dt]}</span>
                        <span style={{color:'#E6EDF3',fontSize:12,fontWeight:600,maxWidth:110,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
                          {p.length > 18 ? p.substring(0,16)+'…' : p}
                        </span>
                      </div>
                      <div style={{display:'flex',alignItems:'center',justifyContent:'center',gap:6}}>
                        <span style={{fontSize:9,color:`${color}cc`,padding:'1px 6px',borderRadius:3,background:`${color}15`,border:`1px solid ${color}25`}}>
                          {DEVICE_LABELS[dt]}
                        </span>
                        <div className="nsa-health-dot" style={{'--device-color': color} as React.CSSProperties}/>
                      </div>
                    </div>
                  </div>
                );
              })}

              {/* ─── SVG Arrow Layer ─── */}
              <svg style={{position:'absolute',top:0,left:0,width:'100%',height:'100%',pointerEvents:'none',zIndex:3}}>
                <defs>
                  <filter id="glow"><feGaussianBlur stdDeviation="2" result="g"/><feMerge><feMergeNode in="g"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
                  <filter id="glow-strong"><feGaussianBlur stdDeviation="3.5" result="g"/><feMerge><feMergeNode in="g"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
                </defs>
                {messages.map((msg, i) => {
                  const y = getRowY(i);
                  const fromX = getColX(msg.from_participant);
                  const toX = getColX(msg.to_participant);
                  if (fromX === toX) return null;
                  const color = getArrowColor(msg, theme);
                  const isErr = msg.severity === 'error' || msg.severity === 'critical';
                  const dimmed = playIdx >= 0 && i > playIdx;
                  const isActive = i === playIdx;
                  const isHovered = i === hoverIdx;
                  const dir = fromX < toX ? 1 : -1;
                  const headX = toX - dir * 4;
                  const dash = getDash(msg);

                  return (
                    <g key={i} className={`nsa-arrow-group ${isErr ? 'nsa-error-arrow' : ''}`}
                       style={{ opacity: dimmed ? 0.15 : 1, transition: 'opacity 0.3s ease', pointerEvents:'auto', '--arrow-color': color } as React.CSSProperties}
                       onClick={() => setSelected(msg)}
                       onMouseEnter={() => setHoverIdx(i)} onMouseLeave={() => setHoverIdx(-1)}>
                      {/* Arrow beam */}
                      <line x1={fromX} y1={y} x2={toX} y2={y}
                            stroke={color} strokeWidth={isActive || isHovered ? 3 : 2}
                            strokeDasharray={dash} strokeLinecap="round"
                            filter={isActive || isHovered ? 'url(#glow-strong)' : isErr ? 'url(#glow)' : undefined}
                            style={{transition:'stroke-width 0.2s ease'}}/>
                      {/* Arrowhead */}
                      <polygon points={`${headX},${y} ${headX - dir*10},${y-5} ${headX - dir*10},${y+5}`}
                               fill={color} filter={isActive ? 'url(#glow-strong)' : undefined}/>
                      {/* Particle orb (on mount / active) */}
                      {(isActive || (playIdx < 0 && i < 6)) && (
                        <circle r={isActive ? 5 : 4} fill={color} filter="url(#glow-strong)">
                          <animate attributeName="cx" from={fromX} to={toX} dur={`${Math.max(0.3, 0.5 / speed)}s`}
                                   begin={playIdx < 0 ? `${i * 0.12}s` : '0s'} fill="freeze" repeatCount="1"/>
                          <animate attributeName="cy" values={`${y};${y}`} dur="0.5s"/>
                          <animate attributeName="opacity" values="0;1;1;0" dur={`${Math.max(0.3, 0.5 / speed)}s`}
                                   begin={playIdx < 0 ? `${i * 0.12}s` : '0s'} fill="freeze"/>
                        </circle>
                      )}
                    </g>
                  );
                })}
                {/* Failure line */}
                {failIdx >= 0 && (
                  <line x1={TS_W} y1={getRowY(failIdx) + ROW_H / 2 + 4} x2={totalW - 20} y2={getRowY(failIdx) + ROW_H / 2 + 4}
                        stroke="#F85149" strokeWidth={1} strokeDasharray="6,4" opacity={0.4}/>
                )}
              </svg>

              {/* ─── HTML Label Layer ─── */}
              {messages.map((msg, i) => {
                const y = getRowY(i);
                const fromX = getColX(msg.from_participant);
                const toX = getColX(msg.to_participant);
                if (fromX === toX) return null;
                const midX = (fromX + toX) / 2;
                const color = getArrowColor(msg, theme);
                const isErr = msg.severity === 'error' || msg.severity === 'critical';
                const dimmed = playIdx >= 0 && i > playIdx;
                const isActive = i === playIdx;

                return (
                  <div key={`lbl-${i}`} style={{ position:'absolute', left: midX, top: y - 28, transform:'translateX(-50%)',
                    opacity: dimmed ? 0.15 : 1, transition:'opacity 0.3s ease', zIndex: isActive ? 10 : 4 }}>
                    {/* Timestamp */}
                    {msg.timestamp && (
                      <div style={{ position:'absolute', left: -(midX - TS_W / 2), top: 14, width: TS_W - 8, textAlign:'right',
                        fontSize:9, fontFamily:'JetBrains Mono, monospace', color:'#4a5568' }}>
                        {msg.timestamp}
                      </div>
                    )}
                    {/* Frosted label */}
                    <div className="nsa-label-pill" onClick={() => setSelected(msg)}
                         style={{ color, borderColor: isErr ? `${color}40` : undefined,
                           boxShadow: isActive ? `0 0 16px ${color}40` : undefined }}>
                      {msg.label}
                      {msg.has_sdp && <span className="nsa-sdp-chip"><AudioLines size={8}/> SDP</span>}
                    </div>
                  </div>
                );
              })}

              {/* ─── Failure Marker ─── */}
              {failIdx >= 0 && (
                <div style={{ position:'absolute', left:0, right:0, top: getRowY(failIdx) + ROW_H / 2 + 2 }}>
                  <div className="nsa-failure-line"/>
                  <div className="nsa-failure-badge"><Zap size={10}/> FAILURE POINT</div>
                </div>
              )}
            </div>
          </div>

          {/* ─── Playback Controller ─── */}
          <div className="nsa-playback">
            <button className="nsa-playback-btn" onClick={stepPrev} title="Previous"><SkipBack size={14}/></button>
            <button className={`nsa-playback-btn ${isPlaying ? 'active' : ''}`} onClick={togglePlay} title={isPlaying ? 'Pause' : 'Play'}>
              {isPlaying ? <Pause size={14}/> : <Play size={14}/>}
            </button>
            <button className="nsa-playback-btn" onClick={stepNext} title="Next"><SkipForward size={14}/></button>

            {/* Scrubber */}
            <div className="nsa-scrubber" onClick={e => {
              const r = e.currentTarget.getBoundingClientRect();
              const pct = (e.clientX - r.left) / r.width;
              setPlayIdx(Math.round(pct * (messages.length - 1)));
              setIsPlaying(false);
            }}>
              <div className="nsa-scrubber-fill" style={{ width: `${messages.length > 1 ? ((playIdx < 0 ? 0 : playIdx) / (messages.length - 1)) * 100 : 0}%` }}/>
              {playIdx >= 0 && (
                <div className="nsa-scrubber-thumb" style={{ left: `${(playIdx / (messages.length - 1)) * 100}%` }}/>
              )}
            </div>

            <button className="nsa-speed-badge" onClick={cycleSpeed} title="Speed">{speed}×</button>
            <span style={{fontSize:10,color:'#4a5568',minWidth:44,textAlign:'right'}}>
              {playIdx < 0 ? '—' : `${playIdx + 1}/${messages.length}`}
            </span>
          </div>
        </>
      )}

      {/* ─── Message Detail Drawer ─── */}
      {selected && (
        <>
          <div className="drawer-overlay" onClick={() => setSelected(null)}/>
          <div className="drawer-panel">
            <div style={{position:'sticky',top:0,zIndex:10,padding:'16px 20px',borderBottom:'1px solid rgba(255,255,255,0.06)',
              background:'linear-gradient(180deg,#0a0f1e,#0a0f1eee)',backdropFilter:'blur(12px)',display:'flex',alignItems:'flex-start',justifyContent:'space-between'}}>
              <div>
                <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4}}>
                  <span style={{padding:'3px 10px',borderRadius:6,fontSize:14,fontWeight:700,fontFamily:'JetBrains Mono, monospace',
                    color: getArrowColor(selected, theme),
                    background:`${getArrowColor(selected, theme)}15`,
                    border:`1px solid ${getArrowColor(selected, theme)}30`}}>
                    {selected.label}
                  </span>
                  {selected.has_sdp && <span className="nsa-sdp-chip"><AudioLines size={9}/> SDP</span>}
                </div>
                <p style={{fontSize:12,color:'#8B949E'}}>
                  {selected.from_participant} → {selected.to_participant}
                  {selected.timestamp && <span style={{marginLeft:8,color:'#4a5568'}}>@ {selected.timestamp}</span>}
                </p>
              </div>
              <div style={{display:'flex',gap:6}}>
                <button onClick={copyRaw} style={{padding:'6px 10px',borderRadius:6,fontSize:11,cursor:'pointer',
                  background:'rgba(255,255,255,0.04)',border:'1px solid rgba(255,255,255,0.08)',color:'#8B949E',
                  display:'flex',alignItems:'center',gap:4,transition:'all 0.15s ease'}}>
                  {copied ? <><Check size={12} color="#3FB950"/> Copied</> : <><Copy size={12}/> Copy</>}
                </button>
                <button onClick={() => setSelected(null)} style={{padding:6,borderRadius:6,cursor:'pointer',
                  background:'rgba(255,255,255,0.04)',border:'1px solid rgba(255,255,255,0.08)',color:'#8B949E'}}>
                  <X size={16}/>
                </button>
              </div>
            </div>

            {/* SDP Summary */}
            {selected.sdp_summary && (
              <div style={{margin:'16px 20px 0',padding:'10px 14px',borderRadius:8,
                background:'rgba(188,140,255,0.08)',border:'1px solid rgba(188,140,255,0.15)'}}>
                <p style={{fontSize:10,color:'#BC8CFF',fontWeight:600,marginBottom:4,textTransform:'uppercase',letterSpacing:0.5}}>SDP Summary</p>
                <p style={{fontSize:13,color:'#E6EDF3',fontFamily:'JetBrains Mono, monospace'}}>{selected.sdp_summary}</p>
              </div>
            )}

            {/* Syntax-highlighted raw message */}
            <div style={{padding:'16px 20px'}}>
              <p style={{fontSize:10,color:'#656D76',fontWeight:600,marginBottom:8,textTransform:'uppercase',letterSpacing:0.5}}>Raw SIP Message</p>
              <pre className="sip-raw-message" style={{fontSize:11.5,lineHeight:1.8}}>
                {selected.raw_message.split('\n').map((line, li) => (
                  <span key={li} className="sip-line">{parseSipLine(line)}{'\n'}</span>
                ))}
              </pre>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
