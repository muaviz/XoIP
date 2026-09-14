import React, { Component, type ReactNode, type ErrorInfo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("[XoIP ErrorBoundary caught exception]:", error, errorInfo);
    this.setState({ error, errorInfo });
  }

  private handleReload = () => {
    window.location.reload();
  };

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-background text-foreground flex items-center justify-center p-6 terminal-grid font-mono">
          <Card className="max-w-2xl w-full border border-destructive/50 bg-card/90 shadow-2xl alert-glow">
            <CardHeader className="border-b border-destructive/20 pb-4">
              <CardTitle className="flex items-center gap-3 text-destructive text-lg font-bold">
                <AlertTriangle className="h-6 w-6 animate-pulse-alert" />
                XoIP Forensics: Runtime Render Exception Caught
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6 space-y-4">
              <p className="text-sm text-muted-foreground">
                An unexpected error interrupted dashboard rendering. The application caught this error to prevent a blank screen.
              </p>
              
              <div className="bg-black/60 p-4 rounded border border-destructive/30 text-xs text-destructive overflow-auto max-h-48">
                <strong>Error:</strong> {this.state.error?.message || "Unknown error"}
                {this.state.error?.stack && (
                  <pre className="mt-2 text-[10px] text-muted-foreground whitespace-pre-wrap">
                    {this.state.error.stack}
                  </pre>
                )}
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <Button variant="outline" size="sm" onClick={this.handleReset} className="border-primary/40 text-primary">
                  Try Recovering View
                </Button>
                <Button size="sm" onClick={this.handleReload} className="bg-primary text-primary-foreground">
                  <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Reload Application
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      );
    }

    return this.props.children;
  }
}
