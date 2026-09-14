import { useState } from "react";
import { ChevronDown, ChevronRight, Shield, AlertTriangle, Clock, Globe, Zap, Binary, Layers } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import type { DissectedPacket } from "@/lib/pcapParser";
import { toUint8Array } from "@/lib/pcapParser";
import type { FilterState } from "./FiltersSidebar";

interface PacketLogProps {
  packets: DissectedPacket[];
  isLiveMode: boolean;
  searchQuery: string;
  filters?: FilterState;
  selectedCallId?: string | null;
}

function formatHexDump(rawBytes?: unknown, maxBytes = 256): string {
  const bytes = toUint8Array(rawBytes);
  if (!bytes || bytes.length === 0) return 'No raw payload available';
  const slice = bytes.subarray(0, maxBytes);
  let out = '';
  for (let i = 0; i < slice.length; i += 16) {
    const chunk = slice.subarray(i, i + 16);
    const offset = i.toString(16).padStart(4, '0');
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(48, ' ');
    const ascii = Array.from(chunk).map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
    out += `${offset}  ${hex}  |${ascii}|\n`;
  }
  if (bytes.length > maxBytes) {
    out += `\n... [${bytes.length - maxBytes} additional bytes truncated]`;
  }
  return out;
}

export const PacketLog = ({ packets, isLiveMode, searchQuery, filters, selectedCallId }: PacketLogProps) => {
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  const toggleRowExpansion = (packetId: string) => {
    setExpandedRows(prev => {
      const newSet = new Set(prev);
      if (newSet.has(packetId)) {
        newSet.delete(packetId);
      } else {
        newSet.add(packetId);
      }
      return newSet;
    });
  };

  const filteredPackets = packets.filter(packet => {
    // Search query filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      const matchesSearch = (
        packet.sourceIP.includes(query) ||
        packet.destIP.includes(query) ||
        packet.sourcePort.toString().includes(query) ||
        packet.destPort.toString().includes(query) ||
        packet.protocol.toLowerCase().includes(query) ||
        packet.method.toLowerCase().includes(query) ||
        packet.status.toLowerCase().includes(query) ||
        (packet.metadata?.['Call-ID'] && packet.metadata['Call-ID'].toLowerCase().includes(query)) ||
        (packet.metadata?.['From'] && packet.metadata['From'].toLowerCase().includes(query)) ||
        (packet.metadata?.['To'] && packet.metadata['To'].toLowerCase().includes(query))
      );
      if (!matchesSearch) return false;
    }

    // Selected call filter
    if (selectedCallId) {
      const packetCallId = packet.metadata?.['Call-ID'] || '';
      if (packetCallId) {
        if (!selectedCallId.includes(packetCallId) && !packetCallId.includes(selectedCallId)) {
          return false;
        }
      }
    }

    // Faceted filters
    if (filters) {
      // Protocol filter
      if (filters.protocols.length > 0) {
        const pLower = packet.protocol.toLowerCase();
        const protocolMatch = filters.protocols.some(p => p.toLowerCase() === pLower || (p === 'tls' && packet.encrypted));
        if (!protocolMatch) return false;
      }

      // Encryption filter
      if (filters.encryption.length > 0) {
        const encryptionMatch = filters.encryption.some(e => {
          if (e === 'encrypted' && packet.encrypted) return true;
          if (e === 'unencrypted' && !packet.encrypted) return true;
          return false;
        });
        if (!encryptionMatch) return false;
      }

      // Alert types filter
      if (filters.alertTypes.length > 0) {
        if (!packet.alertType || !filters.alertTypes.includes(packet.alertType)) {
          return false;
        }
      }

      // Call types filter
      if (filters.callTypes.length > 0) {
        if (!packet.callType || !filters.callTypes.includes(packet.callType)) {
          return false;
        }
      }
    }

    return true;
  });

  const getProtocolColor = (protocol: string) => {
    switch (protocol) {
      case 'SIP': return 'text-primary border-primary/40 bg-primary/10';
      case 'RTP': return 'text-success border-success/40 bg-success/10';
      case 'RTCP': return 'text-accent border-accent/40 bg-accent/10';
      case 'TLS': return 'text-yellow-400 border-yellow-400/40 bg-yellow-400/10';
      default: return 'text-muted-foreground border-border/40';
    }
  };

  if (packets.length === 0) {
    return (
      <Card className="border border-muted/30">
        <CardContent className="p-12 text-center">
          <div className="text-muted-foreground">
            <Globe className="h-12 w-12 mx-auto mb-4 opacity-50 text-primary" />
            <p className="text-foreground font-semibold">No Network Packets Loaded</p>
            <p className="text-xs text-muted-foreground mt-1">
              Upload a PCAP capture file above or enable Live Capture to start forensic inspection
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border border-primary/20 data-stream">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-primary text-base">
            <Zap className="h-5 w-5" />
            Forensic Packet Dissection Log
            {isLiveMode && (
              <Badge variant="outline" className="ml-2 animate-pulse-alert border-primary text-primary">
                LIVE STREAM
              </Badge>
            )}
          </CardTitle>
          <div className="text-xs text-muted-foreground font-mono">
            Showing <span className="text-primary font-bold">{filteredPackets.length}</span> of {packets.length} packets
            {selectedCallId && <span className="ml-2 text-xs text-accent">(Filtered by Session ID)</span>}
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="p-0">
        <div className="max-h-[550px] overflow-auto">
          {/* Table Header */}
          <div className="grid grid-cols-12 gap-2 p-3 border-b border-primary/20 text-xs font-semibold text-primary bg-secondary/30 sticky top-0 z-10 backdrop-blur-sm">
            <div className="col-span-2">Time / Offset</div>
            <div className="col-span-2">Source (IP:Port)</div>
            <div className="col-span-2">Destination (IP:Port)</div>
            <div className="col-span-1">Protocol</div>
            <div className="col-span-2">Method / Summary</div>
            <div className="col-span-2">Status / Details</div>
            <div className="col-span-1 text-right">Length</div>
          </div>
          
          <div className="divide-y divide-border/20 font-mono">
            {filteredPackets.map((packet, index) => (
              <Collapsible key={packet.id} open={expandedRows.has(packet.id)}>
                <CollapsibleTrigger asChild>
                  <div
                    className={`grid grid-cols-12 gap-2 p-3 text-xs hover:bg-secondary/40 cursor-pointer transition-colors ${
                      packet.suspicious ? 'bg-destructive/10 border-l-2 border-l-destructive' : ''
                    } ${expandedRows.has(packet.id) ? 'bg-secondary/30' : ''}`}
                    onClick={() => toggleRowExpansion(packet.id)}
                  >
                    <div className="col-span-2 flex items-center gap-1.5 text-muted-foreground text-[11px]">
                      {expandedRows.has(packet.id) ? (
                        <ChevronDown className="h-3 w-3 text-primary shrink-0" />
                      ) : (
                        <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
                      )}
                      <Clock className="h-3 w-3 shrink-0" />
                      <span>{new Date(packet.rawTimestampMs || packet.timestamp).toLocaleTimeString()}.{String(new Date(packet.rawTimestampMs || packet.timestamp).getMilliseconds()).padStart(3, '0')}</span>
                    </div>
                    
                    <div className="col-span-2 text-foreground truncate" title={`${packet.sourceIP}:${packet.sourcePort}`}>
                      {packet.sourceIP}<span className="text-muted-foreground">:{packet.sourcePort}</span>
                    </div>
                    <div className="col-span-2 text-foreground truncate" title={`${packet.destIP}:${packet.destPort}`}>
                      {packet.destIP}<span className="text-muted-foreground">:{packet.destPort}</span>
                    </div>
                    
                    <div className="col-span-1">
                      <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${getProtocolColor(packet.protocol)}`}>
                        {packet.protocol}
                      </Badge>
                    </div>
                    
                    <div className="col-span-2 truncate font-semibold text-foreground" title={packet.method}>
                      {packet.method}
                    </div>
                    
                    <div className="col-span-2 flex items-center gap-1.5 truncate">
                      <span className={`truncate ${
                        packet.status.includes('200') ? 'text-success' :
                        packet.status.startsWith('4') || packet.status.startsWith('5') || packet.status.startsWith('6') ? 'text-destructive font-bold' :
                        'text-muted-foreground'
                      }`} title={packet.status}>
                        {packet.status}
                      </span>
                      {packet.encrypted && <Shield className="h-3 w-3 text-success shrink-0" />}
                      {packet.suspicious && <AlertTriangle className="h-3 w-3 text-destructive animate-pulse-alert shrink-0" />}
                    </div>
                    
                    <div className="col-span-1 text-right text-muted-foreground text-[11px]">
                      {packet.size} B
                    </div>
                  </div>
                </CollapsibleTrigger>
                
                <CollapsibleContent>
                  <div className="px-6 py-4 bg-muted/30 border-t border-b border-primary/20 space-y-4">
                    <div className="grid grid-cols-2 gap-6 text-xs">
                      {/* Packet Overview */}
                      <div className="space-y-2 bg-card/60 p-3 rounded border border-primary/10">
                        <div className="flex items-center gap-1.5 text-primary font-semibold border-b border-primary/10 pb-1 mb-2">
                          <Layers className="h-3.5 w-3.5" />
                          <span>Layer & Session Metadata</span>
                        </div>
                        <div className="space-y-1 font-mono text-[11px]">
                          <div><span className="text-muted-foreground">Packet ID:</span> {packet.id}</div>
                          <div><span className="text-muted-foreground">Wire Length:</span> {packet.size} bytes</div>
                          <div><span className="text-muted-foreground">L4 Transport:</span> {packet.sourcePort} → {packet.destPort}</div>
                          <div><span className="text-muted-foreground">Encrypted:</span> {packet.encrypted ? 'Yes (TLS/SRTP)' : 'No (Cleartext)'}</div>
                          <div>
                            <span className="text-muted-foreground">Security Alert:</span>{' '}
                            {packet.suspicious ? (
                              <span className="text-destructive font-bold">{packet.alertType || 'Suspicious Traffic'}</span>
                            ) : (
                              <span className="text-success">Normal</span>
                            )}
                          </div>
                          {packet.callType && (
                            <div><span className="text-muted-foreground">Call Direction:</span> {packet.callType.toUpperCase()}</div>
                          )}
                        </div>
                      </div>
                      
                      {/* Deep Protocol Dissection */}
                      <div className="space-y-2 bg-card/60 p-3 rounded border border-primary/10">
                        <div className="flex items-center gap-1.5 text-primary font-semibold border-b border-primary/10 pb-1 mb-2">
                          <Binary className="h-3.5 w-3.5" />
                          <span>Dissected Protocol Headers</span>
                        </div>
                        <div className="space-y-1 font-mono text-[11px] max-h-[160px] overflow-auto">
                          {packet.metadata && Object.keys(packet.metadata).length > 0 ? (
                            Object.entries(packet.metadata).map(([key, value]) => (
                              <div key={key} className="break-all">
                                <span className="text-primary/70">{key}:</span> {String(value)}
                              </div>
                            ))
                          ) : (
                            <span className="text-muted-foreground">No specific header metadata parsed</span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Raw Packet Hex / ASCII Forensics Dump */}
                    {expandedRows.has(packet.id) && (
                      <div className="bg-card/80 p-3 rounded border border-primary/20">
                        <div className="flex items-center justify-between border-b border-primary/10 pb-1 mb-2 text-xs font-semibold text-primary">
                          <span className="flex items-center gap-1.5">
                            <Binary className="h-3.5 w-3.5" />
                            Raw Packet Bytes & ASCII Dump ({toUint8Array(packet.payloadBytes || packet.rawBytes)?.length || 0} bytes)
                          </span>
                        </div>
                        <pre className="text-[10px] font-mono text-foreground/90 overflow-x-auto p-2 bg-black/40 rounded">
                          {formatHexDump(packet.payloadBytes || packet.rawBytes)}
                        </pre>
                      </div>
                    )}
                  </div>
                </CollapsibleContent>
              </Collapsible>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
