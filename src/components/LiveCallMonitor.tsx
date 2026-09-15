import { useEffect, useState, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { 
  Phone, 
  PhoneCall, 
  PhoneOff, 
  Clock, 
  Users, 
  AlertTriangle,
  Activity,
  Timer,
  PhoneIncoming,
  Play,
  Square,
  Download,
  Volume2
} from "lucide-react";
import { CallFlowAnalyzer, CallFlowAnalyzerState, CallSession } from "@/lib/callFlowAnalyzer";
import { AudioDecoder } from "@/lib/audioDecoder";
import { toUint8Array } from "@/lib/pcapParser";

interface LiveCallMonitorProps {
  analyzer: CallFlowAnalyzer;
  onCallSelect?: (callId: string) => void;
}

export const LiveCallMonitor = ({ analyzer, onCallSelect }: LiveCallMonitorProps) => {
  const [state, setState] = useState<CallFlowAnalyzerState>(analyzer.getState());
  const [selectedCall, setSelectedCall] = useState<string | null>(null);
  const [isPlayingAudio, setIsPlayingAudio] = useState(false);
  const audioContextRef = useRef<AudioContext | null>(null);
  const audioSourceRef = useRef<AudioBufferSourceNode | null>(null);

  useEffect(() => {
    const unsubscribe = analyzer.subscribe(setState);
    return unsubscribe;
  }, [analyzer]);

  useEffect(() => {
    return () => {
      if (audioSourceRef.current) {
        try { audioSourceRef.current.stop(); } catch { /* ignore stop errors */ }
        audioSourceRef.current = null;
      }
      if (audioContextRef.current && audioContextRef.current.state !== 'closed') {
        try { audioContextRef.current.close(); } catch { /* ignore close errors */ }
        audioContextRef.current = null;
      }
    };
  }, []);

  const getCallStateColor = (state: CallSession['state']) => {
    switch (state) {
      case 'initiated': return 'text-blue-400';
      case 'trying': return 'text-yellow-400';
      case 'ringing': return 'text-orange-400';
      case 'answered': return 'text-green-400';
      case 'ended': return 'text-muted-foreground';
      case 'failed': return 'text-red-400';
      default: return 'text-muted-foreground';
    }
  };

  const getCallStateIcon = (state: CallSession['state']) => {
    switch (state) {
      case 'initiated': return PhoneCall;
      case 'trying': return Timer;
      case 'ringing': return PhoneIncoming;
      case 'answered': return Phone;
      case 'ended': return PhoneOff;
      case 'failed': return AlertTriangle;
      default: return Phone;
    }
  };

  const formatDuration = (ms?: number) => {
    if (!ms) return '0s';
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    }
    if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    }
    return `${seconds}s`;
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString();
  };

  const handleCallClick = (call: CallSession) => {
    const nextCall = call.id === selectedCall ? null : call.id;
    setSelectedCall(nextCall);
    onCallSelect?.(nextCall || '');
  };

  // Audio Playback for Calls with RTP audio bytes
  const playCallAudio = (call: CallSession) => {
    if (!call.audioBytesList || call.audioBytesList.length === 0) return;

    try {
      if (!audioContextRef.current) {
        const AudioContextClass = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
        audioContextRef.current = new AudioContextClass();
      }
      const ctx = audioContextRef.current;
      if (ctx.state === 'suspended') {
        ctx.resume();
      }

      // Concatenate audio chunks safely
      const validChunks: Uint8Array[] = [];
      let totalLength = 0;
      for (const rawChunk of call.audioBytesList) {
        const u8 = toUint8Array(rawChunk);
        if (u8 && u8.length > 0) {
          validChunks.push(u8);
          totalLength += u8.length;
        }
      }
      if (validChunks.length === 0) return;

      const combined = new Uint8Array(totalLength);
      let offset = 0;
      for (const chunk of validChunks) {
        combined.set(chunk, offset);
        offset += chunk.length;
      }

      const payloadType = call.rtpPayloadType !== undefined ? call.rtpPayloadType : 0;
      const audioBuffer = AudioDecoder.decodeG711ToAudioBuffer(combined, payloadType, ctx);

      if (audioSourceRef.current) {
        audioSourceRef.current.stop();
      }

      const source = ctx.createBufferSource();
      source.buffer = audioBuffer;
      source.connect(ctx.destination);
      source.onended = () => {
        setIsPlayingAudio(false);
      };

      audioSourceRef.current = source;
      source.start(0);
      setIsPlayingAudio(true);
    } catch (err) {
      console.error('Audio playback failed:', err);
      setIsPlayingAudio(false);
    }
  };

  const stopCallAudio = () => {
    if (audioSourceRef.current) {
      audioSourceRef.current.stop();
      audioSourceRef.current = null;
    }
    setIsPlayingAudio(false);
  };

  const downloadCallAudio = (call: CallSession) => {
    if (!call.audioBytesList || call.audioBytesList.length === 0) return;

    const validChunks: Uint8Array[] = [];
    let totalLength = 0;
    for (const rawChunk of call.audioBytesList) {
      const u8 = toUint8Array(rawChunk);
      if (u8 && u8.length > 0) {
        validChunks.push(u8);
        totalLength += u8.length;
      }
    }
    if (validChunks.length === 0) return;

    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of validChunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }

    const payloadType = call.rtpPayloadType !== undefined ? call.rtpPayloadType : 0;
    const wavBlob = AudioDecoder.pcmToWav(combined, payloadType);
    const url = URL.createObjectURL(wavBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `voip-audio-${call.fromNumber || 'caller'}-to-${call.toNumber || 'callee'}.wav`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const activeCalls = Array.from(state.activeCalls.values());
  const recentCalls = state.completedCalls.slice(0, 10);
  const currentSelectedSession = selectedCall
    ? (state.activeCalls.get(selectedCall) || state.completedCalls.find(c => c.id === selectedCall))
    : null;

  return (
    <div className="space-y-4">
      {/* Stats Overview */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="border-primary/20 bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Active Sessions</p>
                <p className="text-2xl font-bold font-mono text-primary">{activeCalls.length}</p>
              </div>
              <div className="p-2 rounded-full bg-primary/10">
                <Phone className="h-5 w-5 text-primary" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Total Calls</p>
                <p className="text-2xl font-bold font-mono text-primary">{state.totalCalls}</p>
              </div>
              <div className="p-2 rounded-full bg-primary/10">
                <Users className="h-5 w-5 text-primary" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Failed Calls</p>
                <p className={`text-2xl font-bold font-mono ${state.failedCalls > 0 ? 'text-destructive' : 'text-primary'}`}>
                  {state.failedCalls}
                </p>
              </div>
              <div className={`p-2 rounded-full ${state.failedCalls > 0 ? 'bg-destructive/10' : 'bg-primary/10'}`}>
                <AlertTriangle className={`h-5 w-5 ${state.failedCalls > 0 ? 'text-destructive' : 'text-primary'}`} />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Avg Duration</p>
                <p className="text-2xl font-bold font-mono text-primary">
                  {formatDuration(state.avgCallDuration)}
                </p>
              </div>
              <div className="p-2 rounded-full bg-primary/10">
                <Clock className="h-5 w-5 text-primary" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Selected Call Audio Player Banner if audio is present */}
      {currentSelectedSession && currentSelectedSession.audioBytesList && currentSelectedSession.audioBytesList.length > 0 && (
        <Card className="border-primary/40 bg-card/80 cyber-glow">
          <CardContent className="p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-full bg-primary/20 text-primary">
                <Volume2 className="h-5 w-5" />
              </div>
              <div>
                <h4 className="text-sm font-semibold text-primary">
                  VoIP Call Audio Stream ({currentSelectedSession.rtpPacketsCount || currentSelectedSession.audioBytesList.length} RTP packets)
                </h4>
                <p className="text-xs text-muted-foreground font-mono">
                  Codec: {currentSelectedSession.codec || 'PCMU (G.711 µ-law)'} • Session: {currentSelectedSession.fromNumber || currentSelectedSession.fromIP} → {currentSelectedSession.toNumber || currentSelectedSession.toIP}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {!isPlayingAudio ? (
                <Button size="sm" onClick={() => playCallAudio(currentSelectedSession)} className="bg-primary text-primary-foreground hover:bg-primary/90">
                  <Play className="h-4 w-4 mr-1 fill-current" /> Play Audio
                </Button>
              ) : (
                <Button size="sm" variant="destructive" onClick={stopCallAudio}>
                  <Square className="h-4 w-4 mr-1 fill-current" /> Stop Audio
                </Button>
              )}
              <Button size="sm" variant="outline" onClick={() => downloadCallAudio(currentSelectedSession)} className="border-primary/30">
                <Download className="h-4 w-4 mr-1" /> Export .WAV
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Live Call Flow */}
      <div className="grid grid-cols-2 gap-4">
        {/* Active Calls */}
        <Card className="border-primary/20 bg-card/50 cyber-glow">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-primary text-sm">
              <Activity className="h-4 w-4 animate-pulse-alert" />
              Active Sessions
              {activeCalls.length > 0 && (
                <Badge variant="outline" className="border-primary text-primary animate-pulse-alert">
                  {activeCalls.length}
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 max-h-[260px] overflow-auto">
            {activeCalls.length === 0 ? (
              <div className="text-center py-6 text-muted-foreground text-xs">
                <Phone className="h-6 w-6 mx-auto mb-2 opacity-50" />
                <p>No active VoIP sessions</p>
              </div>
            ) : (
              activeCalls.map((call) => {
                const StateIcon = getCallStateIcon(call.state);
                const isSelected = selectedCall === call.id;
                
                return (
                  <Button
                    key={call.id}
                    variant="ghost"
                    className={`w-full justify-start p-3 h-auto ${
                      isSelected ? 'bg-primary/10 border border-primary/30' : 'hover:bg-secondary/50'
                    }`}
                    onClick={() => handleCallClick(call)}
                  >
                    <div className="flex items-center justify-between w-full">
                      <div className="flex items-center gap-3">
                        <StateIcon className={`h-4 w-4 ${getCallStateColor(call.state)}`} />
                        <div className="text-left">
                          <div className="font-mono text-xs font-semibold">
                            {call.fromNumber || call.fromIP} → {call.toNumber || call.toIP}
                          </div>
                          <div className="text-[11px] text-muted-foreground">
                            {formatTime(call.startTime)} • {call.state.toUpperCase()}
                            {call.codec && ` • ${call.codec}`}
                          </div>
                        </div>
                      </div>
                      <div className="text-xs text-primary font-mono font-semibold">
                        {call.state === 'answered' ? formatDuration(Date.now() - call.startTime.getTime()) : call.state}
                      </div>
                    </div>
                  </Button>
                );
              })
            )}
          </CardContent>
        </Card>

        {/* Recent Completed Calls */}
        <Card className="border-primary/20 bg-card/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-primary text-sm">
              <Clock className="h-4 w-4" />
              Completed Calls ({recentCalls.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 max-h-[260px] overflow-auto">
            {recentCalls.length === 0 ? (
              <div className="text-center py-6 text-muted-foreground text-xs">
                <PhoneOff className="h-6 w-6 mx-auto mb-2 opacity-50" />
                <p>No completed call sessions yet</p>
              </div>
            ) : (
              recentCalls.map((call) => {
                const StateIcon = getCallStateIcon(call.state);
                const isSelected = selectedCall === call.id;
                
                return (
                  <div
                    key={call.id}
                    onClick={() => handleCallClick(call)}
                    className={`p-2.5 rounded-lg border cursor-pointer transition-colors ${
                      isSelected ? 'border-primary/60 bg-primary/10' :
                      call.failed ? 'border-destructive/30 bg-destructive/5 hover:bg-destructive/10' : 'border-border/30 bg-secondary/20 hover:bg-secondary/40'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2.5">
                        <StateIcon className={`h-4 w-4 ${getCallStateColor(call.state)}`} />
                        <div>
                          <div className="font-mono text-xs font-semibold">
                            {call.fromNumber || call.fromIP} → {call.toNumber || call.toIP}
                          </div>
                          <div className="text-[11px] text-muted-foreground">
                            {formatTime(call.startTime)} • {formatDuration(call.duration)}
                            {call.codec && ` • ${call.codec}`}
                            {call.failed && call.failureReason && (
                              <span className="text-destructive ml-1.5">• {call.failureReason}</span>
                            )}
                          </div>
                        </div>
                      </div>

                      {call.audioBytesList && call.audioBytesList.length > 0 && (
                        <Badge variant="outline" className="text-[10px] border-primary/40 text-primary">
                          <Volume2 className="h-3 w-3 mr-1" /> Audio
                        </Badge>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
