import { useState, useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Search, Upload, Radio, Download, Activity } from "lucide-react";
import { FileUpload } from "./FileUpload";
import { PacketLog } from "./PacketLog";
import { FiltersSidebar } from "./FiltersSidebar";
import { LiveCallMonitor } from "./LiveCallMonitor";
import { CallFlowAnalyzer } from "@/lib/callFlowAnalyzer";

interface FilterState {
  protocols: string[];
  encryption: string[];
  alertTypes: string[];
  callTypes: string[];
}

export const Dashboard = () => {
  const [liveCaptureMode, setLiveCaptureMode] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [filters, setFilters] = useState<FilterState>({
    protocols: [],
    encryption: [],
    alertTypes: [],
    callTypes: []
  });
  const [selectedCallId, setSelectedCallId] = useState<string | null>(null);
  
  const callAnalyzer = useRef(new CallFlowAnalyzer());

  useEffect(() => {
    const cleanup = setInterval(() => {
      callAnalyzer.current.cleanup();
    }, 60000); // Cleanup every minute

    return () => clearInterval(cleanup);
  }, []);

  const handleFileSelect = (file: File) => {
    setSelectedFile(file);
    setLiveCaptureMode(false);
  };

  const toggleLiveCapture = () => {
    setLiveCaptureMode(!liveCaptureMode);
    if (!liveCaptureMode) {
      setSelectedFile(null);
    }
  };

  const handlePacketAnalyzed = (packet: any) => {
    callAnalyzer.current.processPacket(packet);
  };

  const handleCallSelect = (callId: string) => {
    setSelectedCallId(callId === selectedCallId ? null : callId);
  };

  return (
    <div className="min-h-screen bg-background terminal-grid">
      {/* Header */}
      <header className="border-b border-primary/20 bg-card/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <h1 className="text-2xl font-bold text-primary cyber-glow">
                XoIP <span className="text-muted-foreground">Forensics</span>
              </h1>
              <div className="h-6 w-px bg-primary/30" />
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Activity className="h-4 w-4" />
                Network Analysis Dashboard
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {/* Global Search */}
              <div className="relative">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search by IP, protocol, method..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10 w-80 bg-secondary/50 border-primary/20 focus:border-primary"
                />
              </div>
              
              {/* Live Capture Toggle */}
              <Button
                onClick={toggleLiveCapture}
                variant={liveCaptureMode ? "default" : "outline"}
                className={`cyber-glow ${liveCaptureMode ? 'animate-pulse-alert' : ''}`}
              >
                <Radio className="h-4 w-4 mr-2" />
                {liveCaptureMode ? "Stop Live" : "Live Capture"}
              </Button>
              
              {/* Export Button */}
              <Button variant="outline" className="border-primary/20">
                <Download className="h-4 w-4 mr-2" />
                Export
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-6">
        <div className="grid grid-cols-12 gap-6 h-[calc(100vh-140px)]">
          {/* Filters Sidebar */}
          <div className="col-span-3">
            <FiltersSidebar 
              filters={filters}
              onFiltersChange={setFilters}
            />
          </div>
          
          {/* Main Content */}
          <div className="col-span-9 space-y-6">
            {/* Live Call Monitor */}
            <LiveCallMonitor 
              analyzer={callAnalyzer.current}
              onCallSelect={handleCallSelect}
            />
            
            {/* File Upload or Live Mode Indicator */}
            {!liveCaptureMode && !selectedFile && (
              <FileUpload onFileSelect={handleFileSelect} />
            )}
            
            {liveCaptureMode && (
              <div className="bg-card border border-primary/30 rounded-lg p-6 cyber-glow">
                <div className="flex items-center justify-center gap-4 text-primary">
                  <div className="animate-pulse-alert">
                    <Radio className="h-8 w-8" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold">Live Capture Mode</h3>
                    <p className="text-muted-foreground">Monitoring network traffic in real-time</p>
                  </div>
                </div>
              </div>
            )}
            
            {/* Packet Log */}
            <PacketLog 
              isLiveMode={liveCaptureMode}
              selectedFile={selectedFile}
              searchQuery={searchQuery}
              filters={filters}
              selectedCallId={selectedCallId}
              onPacketAnalyzed={handlePacketAnalyzed}
            />
          </div>
        </div>
      </div>
    </div>
  );
};
