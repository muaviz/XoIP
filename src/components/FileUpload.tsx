import { useCallback } from "react";
import { useDropzone } from "react-dropzone";
import { Upload, FileText, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

interface FileUploadProps {
  onFileSelect: (file: File) => void;
}

export const FileUpload = ({ onFileSelect }: FileUploadProps) => {
  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      onFileSelect(acceptedFiles[0]);
    }
  }, [onFileSelect]);

  const { getRootProps, getInputProps, isDragActive, acceptedFiles } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.tcpdump.pcap': ['.pcap', '.pcapng'],
      'application/octet-stream': ['.cap']
    },
    maxFiles: 1
  });

  return (
    <Card className="border-dashed border-2 border-primary/30 bg-card/50 hover:border-primary/50 transition-colors cyber-glow">
      <CardContent className="p-8">
        <div {...getRootProps()} className="cursor-pointer">
          <input {...getInputProps()} />
          <div className="text-center space-y-4">
            <div className="mx-auto w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center">
              {isDragActive ? (
                <Upload className="h-8 w-8 text-primary animate-bounce" />
              ) : (
                <FileText className="h-8 w-8 text-primary" />
              )}
            </div>
            
            <div className="space-y-2">
              <h3 className="text-lg font-semibold text-primary">
                {isDragActive ? "Drop PCAP file here" : "Upload PCAP File"}
              </h3>
              <p className="text-muted-foreground">
                {isDragActive 
                  ? "Release to upload your packet capture file"
                  : "Drag and drop your .pcap, .pcapng, or .cap file here, or click to browse"
                }
              </p>
            </div>
            
            {!isDragActive && (
              <Button variant="outline" className="border-primary/20">
                <Upload className="h-4 w-4 mr-2" />
                Browse Files
              </Button>
            )}
            
            {acceptedFiles.length > 0 && (
              <div className="mt-4 p-3 bg-success/10 border border-success/30 rounded-lg">
                <div className="flex items-center gap-2 text-success">
                  <FileText className="h-4 w-4" />
                  <span className="text-sm font-medium">
                    {acceptedFiles[0].name} ({(acceptedFiles[0].size / 1024 / 1024).toFixed(2)} MB)
                  </span>
                </div>
              </div>
            )}
            
            <div className="text-xs text-muted-foreground space-y-1">
              <div className="flex items-center justify-center gap-2">
                <AlertCircle className="h-3 w-3" />
                <span>Supported formats: .pcap, .pcapng, .cap</span>
              </div>
              <p>Maximum file size: 500MB</p>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
