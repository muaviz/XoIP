import { useState } from "react";
import { 
  X, 
  Copy, 
  Check, 
  ShieldAlert, 
  CheckCircle2, 
  Layers, 
  Binary, 
  FileCode, 
  Clock, 
  Globe, 
  Zap,
  Lock,
  Download
} from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { DissectedPacket } from "@/lib/pcapParser";
import { toUint8Array } from "@/lib/pcapParser";
import { useToast } from "@/hooks/use-toast";

interface PacketDetailsModalProps {
  packet: DissectedPacket | null;
  isOpen: boolean;
  onClose: () => void;
  onFilterByValue?: (field: string, value: string) => void;
}

function formatFullHex(rawBytes?: unknown): { hexLines: string[]; totalBytes: number } {
  const bytes = toUint8Array(rawBytes);
  if (!bytes || bytes.length === 0) return { hexLines: ['No payload bytes available'], totalBytes: 0 };

  const hexLines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.subarray(i, i + 16);
    const offset = i.toString(16).padStart(4, '0');
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(48, ' ');
    const ascii = Array.from(chunk).map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
    hexLines.push(`${offset}  ${hex}  |${ascii}|`);
  }
  return { hexLines, totalBytes: bytes.length };
}

export const PacketDetailsModal = ({
  packet,
  isOpen,
  onClose,
  onFilterByValue
}: PacketDetailsModalProps) => {
  const { toast } = useToast();
  const [copiedField, setCopiedField] = useState<string | null>(null);

  if (!packet) return null;

  const { hexLines, totalBytes } = formatFullHex(packet.payloadBytes || packet.rawBytes);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(label);
    toast({
      title: "Copied to Clipboard",
      description: `Copied ${label} to clipboard.`
    });
    setTimeout(() => setCopiedField(null), 2000);
  };

  const getRawAscii = () => {
    const bytes = toUint8Array(packet.payloadBytes || packet.rawBytes);
    if (!bytes) return '';
    let str = '';
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      str += (b >= 32 && b <= 126) || b === 10 || b === 13 ? String.fromCharCode(b) : '.';
    }
    return str;
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-4xl max-h-[88vh] overflow-hidden flex flex-col bg-card/95 border-primary/30 cyber-glow font-mono p-0">
        <DialogHeader className="p-5 border-b border-primary/20 bg-secondary/30">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10 text-primary">
                <Layers className="h-5 w-5" />
              </div>
              <div>
                <DialogTitle className="text-base text-primary font-bold flex items-center gap-2">
                  <span>Packet Forensic Dissection: {packet.id}</span>
                  <Badge variant="outline" className="text-xs border-primary/40 text-primary">
                    {packet.protocol}
                  </Badge>
                  {packet.encrypted && (
                    <Badge variant="outline" className="text-xs border-success/40 text-success">
                      <Lock className="h-3 w-3 mr-1" /> TLS/Encrypted
                    </Badge>
                  )}
                </DialogTitle>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {packet.sourceIP}:{packet.sourcePort} ➔ {packet.destIP}:{packet.destPort} ({packet.size} bytes on wire)
                </p>
              </div>
            </div>
          </div>
        </DialogHeader>

        {/* Threat Alert Banner if flagged */}
        {packet.suspicious && (
          <div className="mx-5 mt-4 p-3 rounded-lg bg-destructive/15 border border-destructive/40 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2 text-destructive font-semibold">
              <ShieldAlert className="h-4 w-4 shrink-0" />
              <span>Security Anomaly Flagged: {packet.alertType || 'Suspicious VoIP packet'}</span>
            </div>
            <Badge variant="destructive" className="text-[10px]">
              Forensic Alert
            </Badge>
          </div>
        )}

        {/* Tab Switcher */}
        <Tabs defaultValue="layers" className="flex-1 flex flex-col overflow-hidden px-5 pt-3">
          <TabsList className="bg-secondary/60 border border-primary/20 grid grid-cols-3 w-full">
            <TabsTrigger value="layers" className="text-xs">
              <Layers className="h-3.5 w-3.5 mr-1.5" /> Protocol Layers Breakdown
            </TabsTrigger>
            <TabsTrigger value="hex" className="text-xs">
              <Binary className="h-3.5 w-3.5 mr-1.5" /> Raw Hex & ASCII Dump ({totalBytes} B)
            </TabsTrigger>
            <TabsTrigger value="json" className="text-xs">
              <FileCode className="h-3.5 w-3.5 mr-1.5" /> JSON Metadata Object
            </TabsTrigger>
          </TabsList>

          {/* Layers Breakdown Content */}
          <TabsContent value="layers" className="flex-1 overflow-auto py-4 space-y-4">
            {/* L2 / L3 Layer Card */}
            <div className="bg-secondary/20 border border-primary/10 rounded-lg p-3.5 space-y-2">
              <div className="flex items-center justify-between border-b border-primary/10 pb-1 text-xs font-bold text-primary">
                <span className="flex items-center gap-1.5">
                  <Globe className="h-3.5 w-3.5" /> Layer 3: Internet Protocol (IPv4/IPv6)
                </span>
                <span className="text-[11px] text-muted-foreground">{packet.timestamp}</span>
              </div>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="flex items-center justify-between p-2 rounded bg-card/60">
                  <span className="text-muted-foreground">Source IP:</span>
                  <div className="flex items-center gap-1.5">
                    <span className="text-foreground font-bold">{packet.sourceIP}</span>
                    {onFilterByValue && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-5 px-1.5 text-[10px] text-primary hover:bg-primary/10"
                        onClick={() => onFilterByValue('ip', packet.sourceIP)}
                        title="Filter packets by this IP"
                      >
                        Filter
                      </Button>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between p-2 rounded bg-card/60">
                  <span className="text-muted-foreground">Destination IP:</span>
                  <div className="flex items-center gap-1.5">
                    <span className="text-foreground font-bold">{packet.destIP}</span>
                    {onFilterByValue && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-5 px-1.5 text-[10px] text-primary hover:bg-primary/10"
                        onClick={() => onFilterByValue('ip', packet.destIP)}
                        title="Filter packets by this IP"
                      >
                        Filter
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* L4 Transport Layer Card */}
            <div className="bg-secondary/20 border border-primary/10 rounded-lg p-3.5 space-y-2">
              <div className="flex items-center justify-between border-b border-primary/10 pb-1 text-xs font-bold text-primary">
                <span className="flex items-center gap-1.5">
                  <Zap className="h-3.5 w-3.5" /> Layer 4: Transport Layer ({packet.sourcePort > 0 ? (packet.protocol === 'TCP' ? 'TCP' : 'UDP') : 'IP'})
                </span>
              </div>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="flex items-center justify-between p-2 rounded bg-card/60">
                  <span className="text-muted-foreground">Source Port:</span>
                  <span className="text-foreground font-bold">{packet.sourcePort}</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-card/60">
                  <span className="text-muted-foreground">Destination Port:</span>
                  <span className="text-foreground font-bold">{packet.destPort}</span>
                </div>
              </div>
            </div>

            {/* L7 Application / Forensic Protocol Metadata */}
            <div className="bg-secondary/20 border border-primary/10 rounded-lg p-3.5 space-y-2">
              <div className="flex items-center justify-between border-b border-primary/10 pb-1 text-xs font-bold text-primary">
                <span className="flex items-center gap-1.5">
                  <FileCode className="h-3.5 w-3.5" /> Layer 7: {packet.protocol} Protocol Metadata & Headers
                </span>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-6 text-[11px] text-primary hover:bg-primary/10"
                  onClick={() => copyToClipboard(JSON.stringify(packet.metadata, null, 2), 'Headers')}
                >
                  {copiedField === 'Headers' ? <Check className="h-3 w-3 mr-1 text-success" /> : <Copy className="h-3 w-3 mr-1" />}
                  Copy Headers
                </Button>
              </div>

              <div className="space-y-1 text-xs">
                {packet.metadata && Object.keys(packet.metadata).length > 0 ? (
                  Object.entries(packet.metadata).map(([k, v]) => (
                    <div key={k} className="flex items-start justify-between p-2 rounded bg-card/60 gap-4">
                      <span className="text-primary/80 font-semibold shrink-0">{k}:</span>
                      <span className="text-foreground text-right break-all">{String(v)}</span>
                    </div>
                  ))
                ) : (
                  <div className="p-3 text-center text-muted-foreground text-xs">
                    No application-specific headers decoded
                  </div>
                )}
              </div>
            </div>
          </TabsContent>

          {/* Hex & ASCII Dump Content */}
          <TabsContent value="hex" className="flex-1 overflow-hidden flex flex-col py-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">
                Hex Offset | 16-Byte Hex Representation | ASCII Characters
              </span>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs border-primary/30 hover:bg-primary/10"
                  onClick={() => copyToClipboard(hexLines.join('\n'), 'Hex Dump')}
                >
                  <Copy className="h-3 w-3 mr-1" /> Copy Hex
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs border-primary/30 hover:bg-primary/10"
                  onClick={() => copyToClipboard(getRawAscii(), 'ASCII Text')}
                >
                  <Copy className="h-3 w-3 mr-1" /> Copy ASCII
                </Button>
              </div>
            </div>

            <div className="flex-1 overflow-auto bg-black/60 p-3 rounded-lg border border-primary/20">
              <pre className="text-[11px] font-mono text-primary/90 leading-relaxed select-text">
                {hexLines.join('\n')}
              </pre>
            </div>
          </TabsContent>

          {/* JSON Metadata Content */}
          <TabsContent value="json" className="flex-1 overflow-hidden flex flex-col py-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Normalized Forensic Packet Schema</span>
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs border-primary/30 hover:bg-primary/10"
                onClick={() => copyToClipboard(JSON.stringify(packet, null, 2), 'JSON Data')}
              >
                <Copy className="h-3 w-3 mr-1" /> Copy JSON
              </Button>
            </div>

            <div className="flex-1 overflow-auto bg-black/60 p-3 rounded-lg border border-primary/20">
              <pre className="text-[11px] font-mono text-accent leading-relaxed select-text">
                {JSON.stringify(packet, null, 2)}
              </pre>
            </div>
          </TabsContent>
        </Tabs>

        {/* Footer */}
        <div className="p-4 border-t border-primary/20 bg-secondary/30 flex items-center justify-between">
          <span className="text-xs text-muted-foreground">
            Wire Length: {packet.size} B • Protocol: {packet.protocol}
          </span>
          <Button size="sm" onClick={onClose} className="bg-primary text-primary-foreground text-xs">
            Close Inspector
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};
