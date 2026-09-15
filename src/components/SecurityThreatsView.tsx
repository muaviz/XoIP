import { useMemo } from "react";
import { 
  ShieldAlert, 
  AlertTriangle, 
  ShieldCheck, 
  Lock, 
  Clock, 
  FileCode, 
  ExternalLink,
  ChevronRight,
  Download
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { DissectedPacket } from "@/lib/pcapParser";
import { useToast } from "@/hooks/use-toast";

interface SecurityThreatsViewProps {
  packets: DissectedPacket[];
  onInspectPacket?: (packet: DissectedPacket) => void;
}

export const SecurityThreatsView = ({
  packets,
  onInspectPacket
}: SecurityThreatsViewProps) => {
  const { toast } = useToast();

  const { suspiciousPackets, threatCategories } = useMemo(() => {
    const suspicious: DissectedPacket[] = [];
    const authFailures: DissectedPacket[] = [];
    const malformed: DissectedPacket[] = [];
    const unusualPorts: DissectedPacket[] = [];
    const failedCalls: DissectedPacket[] = [];
    const scannerDetected: DissectedPacket[] = [];

    for (const p of packets) {
      if (p.suspicious) {
        suspicious.push(p);
      }
      if (p.alertType === 'auth-failure') {
        authFailures.push(p);
      } else if (p.alertType === 'malformed') {
        malformed.push(p);
      } else if (p.alertType === 'unusual-ports') {
        unusualPorts.push(p);
      } else if (p.alertType === 'failed-calls') {
        failedCalls.push(p);
      }

      const ua = String(p.metadata?.['User-Agent'] || '').toLowerCase();
      if (ua.includes('sipvicious') || ua.includes('friendly-scanner') || ua.includes('sunday') || ua.includes('scanner')) {
        scannerDetected.push(p);
      }
    }

    return {
      suspiciousPackets: suspicious,
      threatCategories: {
        authFailures,
        malformed,
        unusualPorts,
        failedCalls,
        scannerDetected
      }
    };
  }, [packets]);

  const exportIncidentReport = () => {
    if (suspiciousPackets.length === 0) return;

    const report = {
      reportType: "XoIP Security & Forensic Incident Report",
      generatedAt: new Date().toISOString(),
      summary: {
        totalInspectedPackets: packets.length,
        totalThreatsFlagged: suspiciousPackets.length,
        authFailures: threatCategories.authFailures.length,
        malformedPackets: threatCategories.malformed.length,
        unusualPortPackets: threatCategories.unusualPorts.length,
        failedCalls: threatCategories.failedCalls.length,
        scannerSignatures: threatCategories.scannerDetected.length
      },
      flaggedIncidents: suspiciousPackets.map(p => ({
        id: p.id,
        timestamp: p.timestamp,
        source: `${p.sourceIP}:${p.sourcePort}`,
        dest: `${p.destIP}:${p.destPort}`,
        protocol: p.protocol,
        alertType: p.alertType || 'Suspicious Traffic',
        method: p.method,
        status: p.status,
        userAgent: p.metadata?.['User-Agent'] || 'Unknown'
      }))
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `xoip-threat-incident-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast({
      title: "Security Incident Report Exported",
      description: `Saved ${suspiciousPackets.length} flagged security events.`
    });
  };

  if (suspiciousPackets.length === 0) {
    return (
      <Card className="border border-success/30 bg-card/50">
        <CardContent className="p-12 text-center font-mono">
          <div className="mx-auto w-16 h-16 rounded-full bg-success/10 flex items-center justify-center mb-4">
            <ShieldCheck className="h-8 w-8 text-success" />
          </div>
          <h3 className="text-base font-bold text-success">Zero Security Threats Detected</h3>
          <p className="text-xs text-muted-foreground mt-1 max-w-md mx-auto">
            All inspected SIP and RTP packets conform to standard RFC specifications without authentication anomalies, scanners, or malformed headers.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6 font-mono">
      {/* Overview Cards */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="border border-destructive/30 bg-card/50 alert-glow">
          <CardContent className="p-4 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground uppercase">Auth Failures</span>
              <Badge variant="destructive" className="text-[10px]">
                {threatCategories.authFailures.length}
              </Badge>
            </div>
            <p className="text-2xl font-bold text-destructive">{threatCategories.authFailures.length}</p>
            <p className="text-[11px] text-muted-foreground">SIP 401/407 Challenge Rejections</p>
          </CardContent>
        </Card>

        <Card className="border border-warning/30 bg-card/50">
          <CardContent className="p-4 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground uppercase">Malformed Packets</span>
              <Badge variant="outline" className="border-warning/40 text-warning text-[10px]">
                {threatCategories.malformed.length}
              </Badge>
            </div>
            <p className="text-2xl font-bold text-warning">{threatCategories.malformed.length}</p>
            <p className="text-[11px] text-muted-foreground">Corrupted / Missing Headers</p>
          </CardContent>
        </Card>

        <Card className="border border-primary/30 bg-card/50">
          <CardContent className="p-4 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground uppercase">Unusual Ports</span>
              <Badge variant="outline" className="border-primary/40 text-primary text-[10px]">
                {threatCategories.unusualPorts.length}
              </Badge>
            </div>
            <p className="text-2xl font-bold text-primary">{threatCategories.unusualPorts.length}</p>
            <p className="text-[11px] text-muted-foreground">Non-standard VoIP Transport</p>
          </CardContent>
        </Card>

        <Card className="border border-destructive/30 bg-card/50">
          <CardContent className="p-4 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground uppercase">Scanner Signatures</span>
              <Badge variant="destructive" className="text-[10px]">
                {threatCategories.scannerDetected.length}
              </Badge>
            </div>
            <p className="text-2xl font-bold text-destructive">{threatCategories.scannerDetected.length}</p>
            <p className="text-[11px] text-muted-foreground">SIP scanning tools detected</p>
          </CardContent>
        </Card>
      </div>

      {/* Flagged Incidents List */}
      <Card className="border border-destructive/30 bg-card/70 cyber-glow">
        <CardHeader className="pb-3 border-b border-primary/10">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-destructive text-sm">
              <ShieldAlert className="h-4 w-4 animate-pulse-alert" />
              Flagged Forensic Security Incidents ({suspiciousPackets.length})
            </CardTitle>
            <Button
              size="sm"
              variant="outline"
              onClick={exportIncidentReport}
              className="border-destructive/30 text-destructive hover:bg-destructive/10 text-xs"
            >
              <Download className="h-3.5 w-3.5 mr-1" />
              Export Threat Report
            </Button>
          </div>
        </CardHeader>

        <CardContent className="p-0 max-h-[500px] overflow-auto divide-y divide-border/20">
          {suspiciousPackets.map((pkt) => (
            <div
              key={pkt.id}
              className="p-4 hover:bg-secondary/30 flex items-center justify-between gap-4 transition-colors"
            >
              <div className="flex items-start gap-3">
                <div className="p-2 rounded bg-destructive/10 text-destructive mt-0.5">
                  <AlertTriangle className="h-4 w-4" />
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Badge variant="destructive" className="text-[10px]">
                      {pkt.alertType || 'Suspicious'}
                    </Badge>
                    <span className="text-xs font-bold text-foreground">{pkt.method}</span>
                    <span className="text-xs text-muted-foreground">•</span>
                    <span className="text-xs text-muted-foreground">{pkt.sourceIP}:{pkt.sourcePort} ➔ {pkt.destIP}:{pkt.destPort}</span>
                  </div>
                  <div className="text-[11px] text-muted-foreground">
                    Status: <span className="text-foreground">{pkt.status}</span>
                    {pkt.metadata?.['User-Agent'] && (
                      <span className="ml-2">• UA: <code className="text-primary">{String(pkt.metadata['User-Agent'])}</code></span>
                    )}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-[11px] text-muted-foreground">
                  {new Date(pkt.rawTimestampMs || pkt.timestamp).toLocaleTimeString()}
                </span>
                {onInspectPacket && (
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => onInspectPacket(pkt)}
                    className="h-7 text-xs text-primary hover:bg-primary/10"
                  >
                    Inspect
                    <ChevronRight className="h-3 w-3 ml-1" />
                  </Button>
                )}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
};
