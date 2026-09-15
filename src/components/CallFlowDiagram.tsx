import { useState, useMemo } from "react";
import { 
  ArrowRight, 
  ArrowLeft, 
  Phone, 
  Clock, 
  Layers, 
  ShieldAlert, 
  CheckCircle2, 
  Info,
  ChevronRight,
  Zap,
  Activity,
  User,
  Server
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { CallSession, SipCallMessage } from "@/lib/callFlowAnalyzer";
import type { DissectedPacket } from "@/lib/pcapParser";

interface CallFlowDiagramProps {
  calls: CallSession[];
  selectedCallId?: string | null;
  onSelectCall?: (callId: string) => void;
  packets?: DissectedPacket[];
  onInspectPacket?: (packet: DissectedPacket) => void;
}

export const CallFlowDiagram = ({
  calls,
  selectedCallId,
  onSelectCall,
  packets = [],
  onInspectPacket
}: CallFlowDiagramProps) => {
  // If a call is selected, use it, otherwise pick first available call
  const activeCall = useMemo(() => {
    if (calls.length === 0) return null;
    if (selectedCallId) {
      return calls.find(c => c.id === selectedCallId || c.callId === selectedCallId) || calls[0];
    }
    return calls[0];
  }, [calls, selectedCallId]);

  const [selectedMsgIndex, setSelectedMsgIndex] = useState<number | null>(null);

  // Get chronological messages for active call
  const messages = useMemo(() => {
    if (!activeCall || !activeCall.sipMessages || activeCall.sipMessages.length === 0) {
      // If call session doesn't have direct sipMessages yet, extract from packets
      if (!activeCall) return [];
      const packetIdSet = new Set(activeCall.packets);
      const callPackets = packets.filter(p => packetIdSet.has(p.id) && p.protocol === 'SIP');
      return callPackets.map((p): SipCallMessage => ({
        packetId: p.id,
        timestamp: new Date(p.rawTimestampMs || p.timestamp),
        rawTimestampMs: p.rawTimestampMs || new Date(p.timestamp).getTime(),
        from: (p.metadata?.['From'] as string) || p.sourceIP,
        to: (p.metadata?.['To'] as string) || p.destIP,
        sourceIP: p.sourceIP,
        destIP: p.destIP,
        sourcePort: p.sourcePort,
        destPort: p.destPort,
        protocol: p.protocol,
        method: p.method,
        status: p.status,
        isResponse: p.method.startsWith('SIP ') || /^[1-6]\d\d/.test(p.status),
        statusCode: parseInt(p.status.split(' ')[0], 10) || undefined,
        cseq: p.metadata?.['CSeq'] as string | undefined,
        details: p.metadata?.['User-Agent'] ? `UA: ${p.metadata['User-Agent']}` : undefined
      }));
    }
    return activeCall.sipMessages;
  }, [activeCall, packets]);

  // Determine endpoints
  const callerEndpoint = activeCall ? `${activeCall.fromNumber || 'Caller'} (${activeCall.fromIP})` : 'Caller';
  const calleeEndpoint = activeCall ? `${activeCall.toNumber || 'Callee/PBX'} (${activeCall.toIP})` : 'Callee / PBX';

  const getMethodBadgeStyle = (msg: SipCallMessage) => {
    const methodUpper = msg.method.toUpperCase();
    const statusUpper = msg.status.toUpperCase();

    if (msg.isResponse) {
      if (statusUpper.includes('200') || statusUpper.includes('OK')) {
        return 'bg-success/20 text-success border-success/40';
      }
      if (statusUpper.includes('180') || statusUpper.includes('183') || statusUpper.includes('RINGING')) {
        return 'bg-warning/20 text-warning border-warning/40';
      }
      if (statusUpper.includes('100') || statusUpper.includes('TRYING')) {
        return 'bg-blue-400/20 text-blue-400 border-blue-400/40';
      }
      if (/^[4-6]\d\d/.test(msg.status) || statusUpper.includes('FAIL') || statusUpper.includes('BUSY') || statusUpper.includes('FORBIDDEN')) {
        return 'bg-destructive/20 text-destructive border-destructive/40';
      }
      return 'bg-accent/20 text-accent border-accent/40';
    }

    if (methodUpper.includes('INVITE')) return 'bg-primary/20 text-primary border-primary/40';
    if (methodUpper.includes('ACK')) return 'bg-emerald-400/20 text-emerald-400 border-emerald-400/40';
    if (methodUpper.includes('BYE')) return 'bg-purple-400/20 text-purple-400 border-purple-400/40';
    if (methodUpper.includes('CANCEL')) return 'bg-destructive/20 text-destructive border-destructive/40';
    return 'bg-secondary text-foreground border-border/40';
  };

  const selectedPacket = useMemo(() => {
    if (selectedMsgIndex === null || !messages[selectedMsgIndex]) return null;
    const msg = messages[selectedMsgIndex];
    return packets.find(p => p.id === msg.packetId) || null;
  }, [selectedMsgIndex, messages, packets]);

  if (calls.length === 0) {
    return (
      <Card className="border border-muted/30">
        <CardContent className="p-12 text-center">
          <div className="text-muted-foreground">
            <Layers className="h-12 w-12 mx-auto mb-4 opacity-50 text-primary" />
            <p className="text-foreground font-semibold">No VoIP Sessions for Call Flow Analysis</p>
            <p className="text-xs text-muted-foreground mt-1">
              Upload a PCAP capture with SIP traffic or enable Live Capture to view interactive sequence ladder diagrams.
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Session Selector Bar */}
      <Card className="border border-primary/20 bg-card/60 cyber-glow">
        <CardContent className="p-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-full bg-primary/10 text-primary">
              <Phone className="h-5 w-5" />
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Selected VoIP Session Ladder
              </div>
              <div className="text-sm font-bold text-foreground font-mono">
                {activeCall?.fromNumber || activeCall?.fromIP} ➔ {activeCall?.toNumber || activeCall?.toIP}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground font-mono">Session:</span>
            <select
              value={activeCall?.id || ''}
              onChange={(e) => onSelectCall?.(e.target.value)}
              className="bg-secondary/60 border border-primary/30 rounded px-3 py-1.5 text-xs font-mono text-foreground focus:outline-none focus:border-primary"
            >
              {calls.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.fromNumber || c.fromIP} → {c.toNumber || c.toIP} ({c.state.toUpperCase()})
                </option>
              ))}
            </select>
          </div>
        </CardContent>
      </Card>

      {/* SIP Sequence Ladder Diagram */}
      <Card className="border border-primary/20 bg-card/40">
        <CardHeader className="pb-3 border-b border-primary/10">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-primary text-base">
              <Layers className="h-5 w-5" />
              SIP Call Flow Sequence Diagram (Wireshark-Style Ladder)
            </CardTitle>
            <div className="flex items-center gap-3 text-xs font-mono text-muted-foreground">
              <span>{messages.length} SIP Transactions</span>
              {activeCall?.rtpPacketsCount ? (
                <Badge variant="outline" className="border-success/40 text-success text-[10px]">
                  {activeCall.rtpPacketsCount} RTP Packets
                </Badge>
              ) : null}
              {activeCall?.codec && (
                <Badge variant="outline" className="border-primary/40 text-primary text-[10px]">
                  Codec: {activeCall.codec}
                </Badge>
              )}
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-6">
          {/* Lifeline Column Headers */}
          <div className="grid grid-cols-12 gap-4 pb-6 border-b border-primary/20 text-center font-mono">
            <div className="col-span-2 text-xs text-muted-foreground font-semibold flex items-center justify-start gap-1.5">
              <Clock className="h-3.5 w-3.5 text-primary" />
              <span>Time / $\Delta t$</span>
            </div>

            <div className="col-span-4 bg-primary/10 border border-primary/30 rounded-lg p-2.5 shadow-sm">
              <div className="flex items-center justify-center gap-2 text-xs font-bold text-primary">
                <User className="h-4 w-4" />
                <span>Endpoint A (Caller)</span>
              </div>
              <div className="text-[11px] text-muted-foreground truncate" title={callerEndpoint}>
                {callerEndpoint}
              </div>
            </div>

            <div className="col-span-2 flex items-center justify-center text-[11px] text-muted-foreground font-semibold">
              <Zap className="h-3.5 w-3.5 mr-1 text-primary animate-pulse-alert" />
              Protocol Exchange
            </div>

            <div className="col-span-4 bg-secondary/50 border border-border/40 rounded-lg p-2.5 shadow-sm">
              <div className="flex items-center justify-center gap-2 text-xs font-bold text-foreground">
                <Server className="h-4 w-4 text-accent" />
                <span>Endpoint B (Callee / SIP Proxy)</span>
              </div>
              <div className="text-[11px] text-muted-foreground truncate" title={calleeEndpoint}>
                {calleeEndpoint}
              </div>
            </div>
          </div>

          {/* Sequence Ladder Messages */}
          <div className="relative py-4 space-y-3">
            {/* Lifeline vertical guides */}
            <div className="absolute left-[33.33%] top-0 bottom-0 w-px bg-primary/20 border-r border-dashed border-primary/30" />
            <div className="absolute right-[16.66%] top-0 bottom-0 w-px bg-primary/20 border-r border-dashed border-primary/30" />

            {messages.map((msg, idx) => {
              const prevTime = idx > 0 ? messages[idx - 1].rawTimestampMs : messages[0].rawTimestampMs;
              const deltaMs = Math.max(0, msg.rawTimestampMs - prevTime);
              const isSelected = selectedMsgIndex === idx;

              // Determine arrow direction (Caller -> Callee is left to right; Callee -> Caller is right to left)
              const isCallerToCallee = (msg.sourceIP === activeCall?.fromIP);

              // Check if RTP media stream started right before ACK or 200 OK
              const showRtpSeparator = (msg.method.includes('ACK') || (msg.isResponse && msg.status.includes('200') && idx > 2));

              return (
                <div key={msg.packetId || idx} className="space-y-3">
                  <div
                    onClick={() => setSelectedMsgIndex(isSelected ? null : idx)}
                    className={`grid grid-cols-12 gap-4 items-center p-2.5 rounded-lg border transition-all cursor-pointer ${
                      isSelected 
                        ? 'border-primary bg-primary/15 shadow-md shadow-primary/10' 
                        : 'border-border/20 bg-card/60 hover:bg-secondary/40 hover:border-primary/30'
                    }`}
                  >
                    {/* Timestamp & Delta */}
                    <div className="col-span-2 text-[11px] font-mono text-muted-foreground space-y-0.5">
                      <div>{msg.timestamp.toLocaleTimeString()}.{String(msg.timestamp.getMilliseconds()).padStart(3, '0')}</div>
                      <div className="text-[10px] text-primary/80 font-bold">
                        +{deltaMs} ms
                      </div>
                    </div>

                    {/* Flow Arrow & Label Container */}
                    <div className="col-span-10">
                      {isCallerToCallee ? (
                        <div className="flex items-center gap-3">
                          <div className="w-2.5 h-2.5 rounded-full bg-primary ring-4 ring-primary/20 shrink-0" />
                          <div className="flex-1 flex items-center">
                            <div className="flex-1 h-0.5 bg-gradient-to-r from-primary to-primary/40 relative">
                              <div className="absolute inset-0 flex items-center justify-center -top-6">
                                <Badge variant="outline" className={`text-xs font-mono font-bold px-2 py-0.5 shadow-sm ${getMethodBadgeStyle(msg)}`}>
                                  {msg.method} {msg.isResponse ? `(${msg.status})` : ''}
                                  {msg.cseq && <span className="ml-1 text-[10px] opacity-75 font-normal">[{msg.cseq}]</span>}
                                </Badge>
                              </div>
                            </div>
                            <ArrowRight className="h-4 w-4 text-primary shrink-0 -ml-1" />
                          </div>
                          <div className="w-2.5 h-2.5 rounded-full bg-primary/40 shrink-0" />
                        </div>
                      ) : (
                        <div className="flex items-center gap-3">
                          <div className="w-2.5 h-2.5 rounded-full bg-primary/40 shrink-0" />
                          <div className="flex-1 flex items-center">
                            <ArrowLeft className="h-4 w-4 text-accent shrink-0 -mr-1" />
                            <div className="flex-1 h-0.5 bg-gradient-to-l from-accent to-accent/40 relative">
                              <div className="absolute inset-0 flex items-center justify-center -top-6">
                                <Badge variant="outline" className={`text-xs font-mono font-bold px-2 py-0.5 shadow-sm ${getMethodBadgeStyle(msg)}`}>
                                  {msg.status || msg.method}
                                  {msg.cseq && <span className="ml-1 text-[10px] opacity-75 font-normal">[{msg.cseq}]</span>}
                                </Badge>
                              </div>
                            </div>
                          </div>
                          <div className="w-2.5 h-2.5 rounded-full bg-accent ring-4 ring-accent/20 shrink-0" />
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Interspersed RTP Media Stream Banner when call is active */}
                  {showRtpSeparator && (activeCall?.rtpPacketsCount || 0) > 0 && (
                    <div className="my-2 p-2.5 bg-success/10 border border-success/30 rounded-lg text-center font-mono text-xs text-success flex items-center justify-center gap-2 animate-pulse-alert">
                      <Activity className="h-4 w-4" />
                      <span>
                        ═══════════ RTP Full-Duplex Audio Stream ({activeCall?.codec || 'G.711 µ-law'}, {activeCall?.rtpPacketsCount} Packets) ═══════════
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Expanded Transaction Inspector */}
          {selectedPacket && (
            <div className="mt-6 pt-6 border-t border-primary/20 bg-secondary/30 p-4 rounded-lg space-y-3 font-mono">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-primary font-bold text-xs">
                  <Info className="h-4 w-4" />
                  <span>Transaction Dissection: {selectedPacket.method} ({selectedPacket.id})</span>
                </div>
                {onInspectPacket && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => onInspectPacket(selectedPacket)}
                    className="h-7 text-xs border-primary/30 hover:bg-primary/10"
                  >
                    Open Deep Hex / Layer Inspector
                    <ChevronRight className="h-3 w-3 ml-1" />
                  </Button>
                )}
              </div>

              <div className="grid grid-cols-2 gap-4 text-xs">
                <div className="bg-card/70 p-3 rounded border border-primary/10 space-y-1">
                  <div className="text-primary font-semibold border-b border-primary/10 pb-1 mb-1">
                    Transport & Addressing
                  </div>
                  <div><span className="text-muted-foreground">Source:</span> {selectedPacket.sourceIP}:{selectedPacket.sourcePort}</div>
                  <div><span className="text-muted-foreground">Destination:</span> {selectedPacket.destIP}:{selectedPacket.destPort}</div>
                  <div><span className="text-muted-foreground">Protocol:</span> {selectedPacket.protocol}</div>
                  <div><span className="text-muted-foreground">Wire Length:</span> {selectedPacket.size} bytes</div>
                </div>

                <div className="bg-card/70 p-3 rounded border border-primary/10 space-y-1">
                  <div className="text-primary font-semibold border-b border-primary/10 pb-1 mb-1">
                    SIP Headers & Status
                  </div>
                  <div className="truncate"><span className="text-muted-foreground">Call-ID:</span> {String(selectedPacket.metadata?.['Call-ID'] || 'N/A')}</div>
                  <div className="truncate"><span className="text-muted-foreground">From:</span> {String(selectedPacket.metadata?.['From'] || 'N/A')}</div>
                  <div className="truncate"><span className="text-muted-foreground">To:</span> {String(selectedPacket.metadata?.['To'] || 'N/A')}</div>
                  <div><span className="text-muted-foreground">CSeq:</span> {String(selectedPacket.metadata?.['CSeq'] || 'N/A')}</div>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};
