import { useState, useEffect } from "react";
import { ChevronDown, ChevronRight, Shield, AlertTriangle, Clock, Globe, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";

interface PacketData {
  id: string;
  timestamp: string;
  sourceIP: string;
  destIP: string;
  protocol: string;
  method: string;
  status: string;
  size: number;
  encrypted: boolean;
  suspicious: boolean;
  callType?: 'incoming' | 'outgoing' | 'internal' | 'conference';
  alertType?: 'failed-calls' | 'malformed' | 'suspicious-ip' | 'auth-failure' | 'unusual-ports';
  metadata: Record<string, any>;
}

interface PacketLogProps {
  isLiveMode: boolean;
  selectedFile: File | null;
  searchQuery: string;
  filters?: {
    protocols: string[];
    encryption: string[];
    alertTypes: string[];
    callTypes: string[];
  };
  selectedCallId?: string | null;
  onPacketAnalyzed?: (packet: PacketData) => void;
}

// Mock data generator for demonstration
const generateMockPacket = (): PacketData => {
  const protocols = ['SIP', 'RTP', 'RTCP', 'UDP', 'TCP', 'TLS'];
  const methods = ['INVITE', 'ACK', 'BYE', 'REGISTER', 'OPTIONS', 'CANCEL', '100 Trying', '180 Ringing', '200 OK'];
  const statuses = ['200 OK', '180 Ringing', '404 Not Found', '486 Busy Here', '401 Unauthorized', '100 Trying'];
  
  const sourceIPs = ['192.168.1.10', '10.0.0.15', '172.16.0.5', '203.0.113.25'];
  const destIPs = ['192.168.1.20', '10.0.0.25', '172.16.0.10', '198.51.100.15'];
  const callTypes: Array<'incoming' | 'outgoing' | 'internal' | 'conference'> = ['incoming', 'outgoing', 'internal', 'conference'];
  const alertTypes: Array<'failed-calls' | 'malformed' | 'suspicious-ip' | 'auth-failure' | 'unusual-ports'> = ['failed-calls', 'malformed', 'suspicious-ip', 'auth-failure', 'unusual-ports'];
  
  const protocol = protocols[Math.floor(Math.random() * protocols.length)];
  const suspicious = Math.random() > 0.9;
  const encrypted = Math.random() > 0.7 || protocol === 'TLS';
  
  return {
    id: Math.random().toString(36).substr(2, 9),
    timestamp: new Date().toISOString(),
    sourceIP: sourceIPs[Math.floor(Math.random() * sourceIPs.length)],
    destIP: destIPs[Math.floor(Math.random() * destIPs.length)],
    protocol,
    method: methods[Math.floor(Math.random() * methods.length)],
    status: statuses[Math.floor(Math.random() * statuses.length)],
    size: Math.floor(Math.random() * 1500) + 100,
    encrypted,
    suspicious,
    callType: Math.random() > 0.3 ? callTypes[Math.floor(Math.random() * callTypes.length)] : undefined,
    alertType: suspicious ? alertTypes[Math.floor(Math.random() * alertTypes.length)] : undefined,
    metadata: {
      'User-Agent': 'Asterisk PBX 18.0.0',
      'Call-ID': `${Math.random().toString(36).substr(2, 15)}@voip.example.com`,
      'CSeq': Math.floor(Math.random() * 1000),
      'Content-Length': Math.floor(Math.random() * 500),
      'From': `<sip:${Math.floor(Math.random() * 9999)}@voip.example.com>`,
      'To': `<sip:${Math.floor(Math.random() * 9999)}@voip.example.com>`
    }
  };
};

export const PacketLog = ({ isLiveMode, selectedFile, searchQuery, filters, selectedCallId, onPacketAnalyzed }: PacketLogProps) => {
  const [packets, setPackets] = useState<PacketData[]>([]);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  // Simulate live packet streaming
  useEffect(() => {
    if (isLiveMode) {
      const interval = setInterval(() => {
        const newPacket = generateMockPacket();
        setPackets(prev => [newPacket, ...prev].slice(0, 100)); // Keep only last 100
        onPacketAnalyzed?.(newPacket);
      }, Math.random() * 2000 + 500); // Random interval between 0.5-2.5 seconds

      return () => clearInterval(interval);
    }
  }, [isLiveMode, onPacketAnalyzed]);

  // Load packets from file (mock implementation)
  useEffect(() => {
    if (selectedFile) {
      // In a real implementation, you would parse the PCAP file here
      const mockPackets = Array.from({ length: 50 }, () => generateMockPacket());
      setPackets(mockPackets);
    }
  }, [selectedFile]);

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
        packet.protocol.toLowerCase().includes(query) ||
        packet.method.toLowerCase().includes(query) ||
        packet.status.toLowerCase().includes(query)
      );
      if (!matchesSearch) return false;
    }

    // Selected call filter
    if (selectedCallId && packet.metadata['Call-ID']) {
      const packetCallId = packet.metadata['Call-ID'].split('@')[0];
      if (!selectedCallId.includes(packetCallId)) return false;
    }

    // Apply filters
    if (filters) {
      // Protocol filter
      if (filters.protocols.length > 0) {
        const protocolMatch = filters.protocols.some(p => 
          packet.protocol.toLowerCase() === p.toLowerCase()
        );
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
      case 'SIP': return 'text-primary';
      case 'RTP': return 'text-success';
      case 'RTCP': return 'text-accent';
      default: return 'text-muted-foreground';
    }
  };

  if (!isLiveMode && !selectedFile) {
    return (
      <Card className="border border-muted/30">
        <CardContent className="p-12 text-center">
          <div className="text-muted-foreground">
            <Globe className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>Upload a PCAP file or enable live capture to view packet data</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border border-primary/20 data-stream">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-primary">
            <Zap className="h-5 w-5" />
            Packet Analysis Log
            {isLiveMode && (
              <Badge variant="outline" className="ml-2 animate-pulse-alert border-primary text-primary">
                LIVE
              </Badge>
            )}
          </CardTitle>
          <div className="text-sm text-muted-foreground">
            {filteredPackets.length} packet{filteredPackets.length !== 1 ? 's' : ''}
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="p-0">
        <div className="max-h-[600px] overflow-auto">
          <div className="grid grid-cols-12 gap-2 p-4 border-b border-primary/10 text-xs font-semibold text-primary bg-secondary/20">
            <div className="col-span-2">Timestamp</div>
            <div className="col-span-2">Source IP</div>
            <div className="col-span-2">Dest IP</div>
            <div className="col-span-1">Protocol</div>
            <div className="col-span-2">Method/Type</div>
            <div className="col-span-2">Status</div>
            <div className="col-span-1">Size</div>
          </div>
          
          <div className="divide-y divide-border/20">
            {filteredPackets.map((packet, index) => (
              <Collapsible key={packet.id}>
                <CollapsibleTrigger asChild>
                  <div
                    className={`grid grid-cols-12 gap-2 p-4 text-sm hover:bg-secondary/30 cursor-pointer transition-colors animate-data-flow ${
                      packet.suspicious ? 'bg-destructive/10 alert-glow' : ''
                    }`}
                    style={{ animationDelay: `${index * 50}ms` }}
                    onClick={() => toggleRowExpansion(packet.id)}
                  >
                    <div className="col-span-2 flex items-center gap-2 font-mono text-xs">
                      {expandedRows.has(packet.id) ? (
                        <ChevronDown className="h-3 w-3" />
                      ) : (
                        <ChevronRight className="h-3 w-3" />
                      )}
                      <Clock className="h-3 w-3 text-muted-foreground" />
                      {new Date(packet.timestamp).toLocaleTimeString()}
                    </div>
                    
                    <div className="col-span-2 font-mono text-foreground">{packet.sourceIP}</div>
                    <div className="col-span-2 font-mono text-foreground">{packet.destIP}</div>
                    
                    <div className="col-span-1">
                      <Badge variant="outline" className={`text-xs ${getProtocolColor(packet.protocol)}`}>
                        {packet.protocol}
                      </Badge>
                    </div>
                    
                    <div className="col-span-2 font-mono">{packet.method}</div>
                    
                    <div className="col-span-2 flex items-center gap-2">
                      <span className={packet.status.includes('200') ? 'text-success' : packet.status.includes('4') || packet.status.includes('5') ? 'text-destructive' : 'text-muted-foreground'}>
                        {packet.status}
                      </span>
                      {packet.encrypted && <Shield className="h-3 w-3 text-success" />}
                      {packet.suspicious && <AlertTriangle className="h-3 w-3 text-destructive animate-pulse-alert" />}
                    </div>
                    
                    <div className="col-span-1 text-muted-foreground font-mono text-xs">
                      {packet.size}B
                    </div>
                  </div>
                </CollapsibleTrigger>
                
                <CollapsibleContent>
                  <div className="px-8 pb-4 bg-muted/20 border-l-2 border-primary/30">
                    <div className="grid grid-cols-2 gap-6 text-xs">
                      <div className="space-y-2">
                        <h4 className="font-semibold text-primary mb-2">Packet Details</h4>
                        <div className="space-y-1 font-mono">
                          <div><span className="text-muted-foreground">ID:</span> {packet.id}</div>
                          <div><span className="text-muted-foreground">Size:</span> {packet.size} bytes</div>
                          <div><span className="text-muted-foreground">Encrypted:</span> {packet.encrypted ? 'Yes' : 'No'}</div>
                          <div><span className="text-muted-foreground">Suspicious:</span> {packet.suspicious ? 'Yes' : 'No'}</div>
                        </div>
                      </div>
                      
                      <div className="space-y-2">
                        <h4 className="font-semibold text-primary mb-2">Metadata</h4>
                        <div className="space-y-1 font-mono">
                          {Object.entries(packet.metadata).map(([key, value]) => (
                            <div key={key}>
                              <span className="text-muted-foreground">{key}:</span> {String(value)}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
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
