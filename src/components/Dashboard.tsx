import { useState, useRef, useEffect, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { 
  Search, 
  Upload, 
  Radio, 
  Download, 
  Activity, 
  Trash2, 
  Wifi, 
  WifiOff, 
  FileDown, 
  FileSpreadsheet, 
  FileCode2,
  CheckCircle2,
  AlertCircle
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { FileUpload } from "./FileUpload";
import { PacketLog } from "./PacketLog";
import { FiltersSidebar, type FilterState } from "./FiltersSidebar";
import { LiveCallMonitor } from "./LiveCallMonitor";
import { SummaryStats } from "./SummaryStats";
import { CallFlowAnalyzer, type CallFlowAnalyzerState } from "@/lib/callFlowAnalyzer";
import { PcapParser, normalizePacket, type DissectedPacket } from "@/lib/pcapParser";
import { useToast } from "@/hooks/use-toast";

export const Dashboard = () => {
  const { toast } = useToast();
  const [liveCaptureMode, setLiveCaptureMode] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const [isParsingFile, setIsParsingFile] = useState(false);
  const [packets, setPackets] = useState<DissectedPacket[]>([]);
  const [selectedCallId, setSelectedCallId] = useState<string | null>(null);

  // Live WebSocket capture state
  const [wsConnected, setWsConnected] = useState(false);
  const [liveInterfaces, setLiveInterfaces] = useState<string[]>(['any', 'lo']);
  const [selectedInterface, setSelectedInterface] = useState<string>('any');
  const [captureFilter, setCaptureFilter] = useState<string>('all');
  const [isCapturingBackend, setIsCapturingBackend] = useState(false);
  const [captureError, setCaptureError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const [filters, setFilters] = useState<FilterState>({
    protocols: [],
    encryption: [],
    alertTypes: [],
    callTypes: []
  });

  const callAnalyzer = useRef(new CallFlowAnalyzer());
  const [analyzerState, setAnalyzerState] = useState<CallFlowAnalyzerState>(callAnalyzer.current.getState());

  useEffect(() => {
    const unsub = callAnalyzer.current.subscribe(setAnalyzerState);
    const cleanupInterval = setInterval(() => {
      callAnalyzer.current.cleanup();
    }, 30000);

    return () => {
      unsub();
      clearInterval(cleanupInterval);
    };
  }, []);

  // Connect to Live Capture WebSocket Server when Live mode is toggled
  useEffect(() => {
    if (liveCaptureMode) {
      const wsUrl = `ws://${window.location.hostname || 'localhost'}:8081/ws`;
      let ws: WebSocket;

      try {
        ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          setWsConnected(true);
          setCaptureError(null);
          toast({
            title: "Live Capture Connected",
            description: `Connected to XoIP telemetry server on port 8081. Ready for real-time packet stream.`
          });
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'packet' && data.packet) {
              const pkt: DissectedPacket = normalizePacket(data.packet);
              setPackets(prev => [pkt, ...prev].slice(0, 5000));
              callAnalyzer.current.processPacket(pkt);
            } else if (data.type === 'connected' || data.type === 'capture_state') {
              if (data.status) {
                if (data.status.availableInterfaces) setLiveInterfaces(data.status.availableInterfaces);
                setIsCapturingBackend(data.status.capturing);
              }
              if (data.capturing !== undefined) {
                setIsCapturingBackend(data.capturing);
              }
            } else if (data.type === 'capture_error') {
              setCaptureError(data.error);
            }
          } catch (e) {
            console.error('Error handling WebSocket message:', e);
          }
        };

        ws.onerror = () => {
          setWsConnected(false);
          setCaptureError("Capture server unavailable at port 8081. Run 'npm run capture' to stream live packets.");
        };

        ws.onclose = () => {
          setWsConnected(false);
          setIsCapturingBackend(false);
        };
      } catch (err: unknown) {
        setCaptureError(err instanceof Error ? err.message : String(err));
      }

      return () => {
        if (wsRef.current) {
          wsRef.current.close();
          wsRef.current = null;
        }
      };
    } else {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      setWsConnected(false);
    }
  }, [liveCaptureMode, toast]);

  const toggleLiveCapture = () => {
    const nextMode = !liveCaptureMode;
    setLiveCaptureMode(nextMode);
    if (nextMode) {
      setSelectedFileName(null);
    }
  };

  const startInterfaceCapture = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      let bpf = 'ip or ip6';
      if (captureFilter === 'voip') {
        bpf = 'port 5060 or port 5061 or port 5080 or (udp and portrange 10000-20000)';
      } else if (captureFilter === 'udp') {
        bpf = 'udp';
      } else if (captureFilter === 'web') {
        bpf = 'port 53 or port 80 or port 443';
      }

      wsRef.current.send(JSON.stringify({
        type: 'start_capture',
        interface: selectedInterface,
        filter: bpf
      }));
      setIsCapturingBackend(true);
      setCaptureError(null);
    }
  };

  const stopInterfaceCapture = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'stop_capture'
      }));
      setIsCapturingBackend(false);
    }
  };

  const triggerLiveSample = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'replay_sample'
      }));
      toast({
        title: "Streaming Live VoIP Session",
        description: "Replaying real SIP call flow and RTP packets over live WebSocket..."
      });
    }
  };

  // Handle Binary PCAP File Upload or Sample Selection
  const handleFileSelect = useCallback(async (fileOrData: File | { name: string; buffer: ArrayBuffer }) => {
    setIsParsingFile(true);
    setLiveCaptureMode(false);
    const fileName = 'name' in fileOrData ? fileOrData.name : 'Uploaded PCAP';
    setSelectedFileName(fileName);

    try {
      const buffer = fileOrData instanceof File ? await fileOrData.arrayBuffer() : fileOrData.buffer;
      const result = await PcapParser.parse(buffer);

      // Reset analyzer and feed real dissected packets
      callAnalyzer.current.reset();
      for (const pkt of result.packets) {
        callAnalyzer.current.processPacket(pkt);
      }

      setPackets(result.packets);

      toast({
        title: "PCAP Dissection Complete",
        description: `Successfully dissected ${result.summary.totalPackets} packets (${result.summary.sipPackets} SIP, ${result.summary.rtpPackets} RTP) from ${fileName}.`
      });
    } catch (err: unknown) {
      console.error('Failed to parse PCAP:', err);
      const errMsg = err instanceof Error ? err.message : "Could not parse binary packet capture.";
      toast({
        variant: "destructive",
        title: "PCAP Parse Error",
        description: errMsg
      });
    } finally {
      setIsParsingFile(false);
    }
  }, [toast]);

  const handleClearWorkspace = () => {
    setPackets([]);
    setSelectedFileName(null);
    setSelectedCallId(null);
    callAnalyzer.current.reset();
    toast({
      title: "Workspace Cleared",
      description: "Reset all packet telemetry and call sessions."
    });
  };

  const handleCallSelect = (callId: string) => {
    setSelectedCallId(callId === selectedCallId ? null : callId);
  };

  // Export handlers
  const exportAsPcap = () => {
    if (packets.length === 0) return;
    const pcapBytes = PcapParser.exportToPcap(packets);
    const blob = new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `xoip-forensics-${Date.now()}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
    toast({ title: "PCAP Exported", description: `Saved ${packets.length} packets to Wireshark PCAP format.` });
  };

  const exportAsJson = () => {
    if (packets.length === 0) return;
    const dump = {
      exportedAt: new Date().toISOString(),
      summary: {
        totalPackets: packets.length,
        totalCalls: analyzerState.totalCalls,
        failedCalls: analyzerState.failedCalls,
        avgDurationMs: analyzerState.avgCallDuration
      },
      calls: {
        active: Array.from(analyzerState.activeCalls.values()),
        completed: analyzerState.completedCalls
      },
      packets: packets.map(p => ({
        id: p.id,
        timestamp: p.timestamp,
        source: `${p.sourceIP}:${p.sourcePort}`,
        dest: `${p.destIP}:${p.destPort}`,
        protocol: p.protocol,
        method: p.method,
        status: p.status,
        size: p.size,
        encrypted: p.encrypted,
        suspicious: p.suspicious,
        alertType: p.alertType,
        metadata: p.metadata
      }))
    };
    const blob = new Blob([JSON.stringify(dump, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `xoip-forensic-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast({ title: "JSON Forensic Report Exported", description: "Saved full metadata and call session logs." });
  };

  const exportAsCsv = () => {
    if (packets.length === 0) return;
    const headers = ['Timestamp', 'SourceIP', 'SourcePort', 'DestIP', 'DestPort', 'Protocol', 'Method', 'Status', 'Size', 'Encrypted', 'Suspicious', 'Alert'];
    const rows = packets.map(p => [
      `"${p.timestamp}"`,
      `"${p.sourceIP}"`,
      p.sourcePort,
      `"${p.destIP}"`,
      p.destPort,
      `"${p.protocol}"`,
      `"${(p.method || '').replace(/"/g, '""')}"`,
      `"${(p.status || '').replace(/"/g, '""')}"`,
      p.size,
      p.encrypted ? 'YES' : 'NO',
      p.suspicious ? 'YES' : 'NO',
      `"${p.alertType || 'none'}"`
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `xoip-packets-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast({ title: "CSV Exported", description: `Exported ${packets.length} packet rows.` });
  };

  return (
    <div className="min-h-screen bg-background terminal-grid">
      {/* Header */}
      <header className="border-b border-primary/20 bg-card/50 backdrop-blur-sm sticky top-0 z-20">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <h1 className="text-2xl font-bold text-primary cyber-glow">
                XoIP <span className="text-muted-foreground">Forensics</span>
              </h1>
              <div className="h-6 w-px bg-primary/30" />
              <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono">
                <Activity className="h-4 w-4 text-primary animate-pulse-alert" />
                Real-Time VoIP Forensics & Protocol Analyzer
              </div>
            </div>
            
            <div className="flex items-center gap-3">
              {/* Global Search */}
              <div className="relative">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Filter by IP, port, protocol, Call-ID, method..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10 w-72 bg-secondary/50 border-primary/20 focus:border-primary text-xs font-mono"
                />
              </div>
              
              {/* Live Capture Toggle */}
              <Button
                onClick={toggleLiveCapture}
                variant={liveCaptureMode ? "default" : "outline"}
                className={`text-xs ${liveCaptureMode ? 'bg-primary text-primary-foreground animate-pulse-alert' : 'border-primary/30'}`}
              >
                <Radio className="h-3.5 w-3.5 mr-1.5" />
                {liveCaptureMode ? "Live Mode Active" : "Live Capture"}
              </Button>

              {/* Clear Workspace Button */}
              {packets.length > 0 && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleClearWorkspace}
                  className="border-destructive/30 text-destructive hover:bg-destructive/10 text-xs"
                  title="Clear all packets and sessions"
                >
                  <Trash2 className="h-3.5 w-3.5 mr-1.5" />
                  Reset
                </Button>
              )}

              {/* Export Dropdown */}
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" className="border-primary/20 text-xs" disabled={packets.length === 0}>
                    <Download className="h-3.5 w-3.5 mr-1.5" />
                    Export
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56 font-mono text-xs">
                  <DropdownMenuLabel>Forensic Export Options</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={exportAsPcap} className="cursor-pointer">
                    <FileDown className="h-4 w-4 mr-2 text-primary" />
                    Wireshark PCAP (.pcap)
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={exportAsJson} className="cursor-pointer">
                    <FileCode2 className="h-4 w-4 mr-2 text-accent" />
                    Full Forensic JSON (.json)
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={exportAsCsv} className="cursor-pointer">
                    <FileSpreadsheet className="h-4 w-4 mr-2 text-success" />
                    Packet Log CSV (.csv)
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-6 space-y-6">
        {/* Real Summary KPI Stats */}
        <SummaryStats packets={packets} analyzerState={analyzerState} />

        <div className="grid grid-cols-12 gap-6">
          {/* Filters Sidebar */}
          <div className="col-span-3">
            <FiltersSidebar 
              filters={filters}
              onFiltersChange={setFilters}
              packets={packets}
            />
          </div>
          
          {/* Main Content */}
          <div className="col-span-9 space-y-6">
            {/* Live Call Monitor */}
            <LiveCallMonitor 
              analyzer={callAnalyzer.current}
              onCallSelect={handleCallSelect}
            />
            
            {/* File Upload when not in Live mode and no file loaded */}
            {!liveCaptureMode && packets.length === 0 && (
              <FileUpload 
                onFileSelect={handleFileSelect} 
                isLoading={isParsingFile}
              />
            )}

            {/* Loaded File Banner */}
            {!liveCaptureMode && selectedFileName && (
              <div className="bg-card/70 border border-primary/30 rounded-lg p-3.5 flex items-center justify-between text-xs font-mono cyber-glow">
                <div className="flex items-center gap-2 text-primary">
                  <CheckCircle2 className="h-4 w-4 text-success" />
                  <span>Loaded Capture: <strong className="text-foreground">{selectedFileName}</strong> ({packets.length} packets dissected)</span>
                </div>
                <Button 
                  variant="ghost" 
                  size="sm" 
                  className="h-7 text-xs text-muted-foreground hover:text-foreground"
                  onClick={() => { setSelectedFileName(null); setPackets([]); callAnalyzer.current.reset(); }}
                >
                  Upload Different File
                </Button>
              </div>
            )}
            
            {/* Live Capture Control Banner */}
            {liveCaptureMode && (
              <div className="bg-card/90 border border-primary/40 rounded-lg p-4 cyber-glow space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {wsConnected ? (
                      <div className="p-2 rounded-full bg-success/20 text-success">
                        <Wifi className="h-5 w-5" />
                      </div>
                    ) : (
                      <div className="p-2 rounded-full bg-destructive/20 text-destructive">
                        <WifiOff className="h-5 w-5" />
                      </div>
                    )}
                    <div>
                      <h3 className="text-sm font-semibold text-primary flex items-center gap-2">
                        Live Network Telemetry
                        <span className={`text-[11px] px-2 py-0.5 rounded-full font-mono ${wsConnected ? 'bg-success/20 text-success' : 'bg-destructive/20 text-destructive'}`}>
                          {wsConnected ? 'WebSocket Connected (Port 8081)' : 'Server Disconnected'}
                        </span>
                      </h3>
                      <p className="text-xs text-muted-foreground">
                        {wsConnected 
                          ? `Ingesting live packets via UDP port 5060 socket listener & system sniffer` 
                          : `Capture daemon not connected on ws://localhost:8081. Start backend with 'npm run capture'`}
                      </p>
                    </div>
                  </div>

                  {wsConnected && (
                    <div className="flex items-center gap-2 font-mono text-xs">
                      <select 
                        value={selectedInterface} 
                        onChange={(e) => setSelectedInterface(e.target.value)}
                        className="bg-secondary/60 border border-primary/30 rounded px-2.5 py-1 text-foreground focus:outline-none focus:border-primary"
                        disabled={isCapturingBackend}
                      >
                        {liveInterfaces.map(iface => (
                          <option key={iface} value={iface}>Interface: {iface}</option>
                        ))}
                      </select>

                      <select 
                        value={captureFilter} 
                        onChange={(e) => setCaptureFilter(e.target.value)}
                        className="bg-secondary/60 border border-primary/30 rounded px-2.5 py-1 text-foreground focus:outline-none focus:border-primary"
                        disabled={isCapturingBackend}
                      >
                        <option value="all">Traffic: All IP Packets (Instant)</option>
                        <option value="voip">Traffic: VoIP Only (SIP/RTP)</option>
                        <option value="udp">Traffic: UDP Packets</option>
                        <option value="web">Traffic: Web (DNS, HTTP, HTTPS)</option>
                      </select>

                      {!isCapturingBackend ? (
                        <Button size="sm" onClick={startInterfaceCapture} className="bg-primary text-primary-foreground text-xs">
                          Start Sniffing ({selectedInterface})
                        </Button>
                      ) : (
                        <Button size="sm" variant="destructive" onClick={stopInterfaceCapture} className="text-xs">
                          Stop Sniffing
                        </Button>
                      )}
                      <Button 
                        size="sm" 
                        variant="outline" 
                        onClick={triggerLiveSample} 
                        className="border-primary/40 text-primary text-xs hover:bg-primary/10"
                        title="Stream real SIP and RTP voice packets over the live WebSocket"
                      >
                        <Radio className="h-3.5 w-3.5 mr-1 text-primary animate-pulse-alert" />
                        Stream Sample Call
                      </Button>
                    </div>
                  )}
                </div>

                {captureError && (
                  <div className="p-3 rounded bg-destructive/10 border border-destructive/30 text-xs space-y-1.5">
                    <div className="flex items-center gap-2 text-destructive font-semibold">
                      <AlertCircle className="h-4 w-4 shrink-0" />
                      <span>{captureError}</span>
                    </div>
                    <div className="text-[11px] text-muted-foreground font-mono pl-6 space-y-1">
                      <p className="text-foreground/90">
                        • <strong>Live UDP Socket Listener</strong> is active on <code>0.0.0.0:5060</code> (no root required; sends from PBX/softphone are captured).
                      </p>
                      <p>
                        • To enable raw interface sniffing with tcpdump without root, run:
                        <code className="ml-1 text-primary bg-secondary/80 px-1 py-0.5 rounded">sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)</code>
                      </p>
                      <p>
                        • Or test live packet ingestion right now by clicking <span className="text-primary font-bold">"Stream Sample Call"</span> above, or running <code className="text-primary bg-secondary/80 px-1 py-0.5 rounded">npm run stream:live</code> in another terminal.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}
            
            {/* Packet Log */}
            <PacketLog 
              packets={packets}
              isLiveMode={liveCaptureMode}
              searchQuery={searchQuery}
              filters={filters}
              selectedCallId={selectedCallId}
            />
          </div>
        </div>
      </div>
    </div>
  );
};
