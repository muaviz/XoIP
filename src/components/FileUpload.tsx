import { useCallback, useState } from "react";
import { useDropzone } from "react-dropzone";
import { Upload, FileText, AlertCircle, FileCode, CheckCircle2, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface FileUploadProps {
  onFileSelect: (file: File | { name: string; buffer: ArrayBuffer }) => void;
  isLoading?: boolean;
}

export const FileUpload = ({ onFileSelect, isLoading = false }: FileUploadProps) => {
  const [loadingSample, setLoadingSample] = useState<string | null>(null);

  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      onFileSelect(acceptedFiles[0]);
    }
  }, [onFileSelect]);

  const { getRootProps, getInputProps, isDragActive, acceptedFiles } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.tcpdump.pcap': ['.pcap', '.pcapng'],
      'application/octet-stream': ['.cap', '.pcap', '.pcapng']
    },
    maxFiles: 1
  });

  const loadSampleTrace = async (samplePath: string, sampleName: string) => {
    setLoadingSample(sampleName);
    try {
      const response = await fetch(samplePath);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const arrayBuffer = await response.arrayBuffer();
      onFileSelect({
        name: sampleName,
        buffer: arrayBuffer
      });
    } catch (err) {
      console.error('Failed to load sample trace:', err);
    } finally {
      setLoadingSample(null);
    }
  };

  return (
    <Card className="border-dashed border-2 border-primary/30 bg-card/50 hover:border-primary/50 transition-colors cyber-glow">
      <CardContent className="p-8">
        <div {...getRootProps()} className="cursor-pointer">
          <input {...getInputProps()} />
          <div className="text-center space-y-4">
            <div className="mx-auto w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center">
              {isLoading ? (
                <Loader2 className="h-8 w-8 text-primary animate-spin" />
              ) : isDragActive ? (
                <Upload className="h-8 w-8 text-primary animate-bounce" />
              ) : (
                <FileText className="h-8 w-8 text-primary" />
              )}
            </div>
            
            <div className="space-y-2">
              <h3 className="text-lg font-semibold text-primary">
                {isLoading ? "Parsing Binary PCAP..." : isDragActive ? "Drop PCAP file here" : "Upload Network Capture File"}
              </h3>
              <p className="text-muted-foreground text-sm">
                {isDragActive 
                  ? "Release to decode binary network packets (.pcap, .pcapng, .cap)"
                  : "Drag and drop your genuine .pcap, .pcapng, or .cap file here, or click to browse"
                }
              </p>
            </div>
            
            {!isDragActive && (
              <Button variant="outline" className="border-primary/20" disabled={isLoading}>
                <Upload className="h-4 w-4 mr-2" />
                Browse PCAP Files
              </Button>
            )}
            
            {acceptedFiles.length > 0 && (
              <div className="mt-4 p-3 bg-success/10 border border-success/30 rounded-lg inline-flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-success" />
                <span className="text-sm font-medium text-success">
                  {acceptedFiles[0].name} ({(acceptedFiles[0].size / 1024).toFixed(1)} KB)
                </span>
              </div>
            )}
            
            <div className="text-xs text-muted-foreground space-y-1">
              <div className="flex items-center justify-center gap-2">
                <AlertCircle className="h-3 w-3" />
                <span>Standard formats: Classic PCAP, PCAPNG, Wireshark, tcpdump, Asterisk/FreeSWITCH</span>
              </div>
            </div>
          </div>
        </div>

        {/* Built-in Forensic Sample Traces */}
        <div className="mt-6 pt-6 border-t border-primary/10">
          <div className="text-center mb-3">
            <span className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">
              Or analyze preloaded forensic captures:
            </span>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-3">
            <Button
              variant="outline"
              size="sm"
              className="border-primary/30 hover:bg-primary/10 text-xs"
              onClick={(e) => {
                e.stopPropagation();
                loadSampleTrace('/samples/voip_call_success.pcap', 'voip_call_success.pcap');
              }}
              disabled={isLoading || loadingSample !== null}
            >
              {loadingSample === 'voip_call_success.pcap' ? (
                <Loader2 className="h-3 w-3 mr-1 animate-spin" />
              ) : (
                <FileCode className="h-3 w-3 mr-1 text-primary" />
              )}
              Complete SIP Call with G.711 Audio (.pcap)
              <Badge variant="secondary" className="ml-2 text-[10px] text-primary">37 pkts</Badge>
            </Button>

            <Button
              variant="outline"
              size="sm"
              className="border-destructive/30 hover:bg-destructive/10 text-xs text-destructive hover:text-destructive"
              onClick={(e) => {
                e.stopPropagation();
                loadSampleTrace('/samples/voip_auth_failure.pcap', 'voip_auth_failure.pcap');
              }}
              disabled={isLoading || loadingSample !== null}
            >
              {loadingSample === 'voip_auth_failure.pcap' ? (
                <Loader2 className="h-3 w-3 mr-1 animate-spin" />
              ) : (
                <AlertCircle className="h-3 w-3 mr-1 text-destructive" />
              )}
              SIP 401 Authentication Failure (.pcap)
              <Badge variant="secondary" className="ml-2 text-[10px] text-destructive">Alert</Badge>
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
