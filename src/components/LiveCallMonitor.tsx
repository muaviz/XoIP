import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { 
  Phone, 
  PhoneCall, 
  PhoneOff, 
  Clock, 
  Users, 
  AlertTriangle,
  Activity,
  Timer,
  PhoneIncoming,
  PhoneOutgoing
} from "lucide-react";
import { CallFlowAnalyzer, CallFlowAnalyzerState, CallSession } from "@/lib/callFlowAnalyzer";

interface LiveCallMonitorProps {
  analyzer: CallFlowAnalyzer;
  onCallSelect?: (callId: string) => void;
}

export const LiveCallMonitor = ({ analyzer, onCallSelect }: LiveCallMonitorProps) => {
  const [state, setState] = useState<CallFlowAnalyzerState>(analyzer.getState());
  const [selectedCall, setSelectedCall] = useState<string | null>(null);

  useEffect(() => {
    const unsubscribe = analyzer.subscribe(setState);
    return unsubscribe;
  }, [analyzer]);

  const getCallStateColor = (state: CallSession['state']) => {
    switch (state) {
      case 'initiated': return 'text-blue-400';
      case 'trying': return 'text-yellow-400';
      case 'ringing': return 'text-orange-400';
      case 'answered': return 'text-green-400';
      case 'ended': return 'text-muted-foreground';
      case 'failed': return 'text-red-400';
      default: return 'text-muted-foreground';
    }
  };

  const getCallStateIcon = (state: CallSession['state']) => {
    switch (state) {
      case 'initiated': return PhoneCall;
      case 'trying': return Timer;
      case 'ringing': return PhoneIncoming;
      case 'answered': return Phone;
      case 'ended': return PhoneOff;
      case 'failed': return AlertTriangle;
      default: return Phone;
    }
  };

  const formatDuration = (ms?: number) => {
    if (!ms) return '0s';
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    }
    if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    }
    return `${seconds}s`;
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString();
  };

  const handleCallClick = (call: CallSession) => {
    setSelectedCall(call.id === selectedCall ? null : call.id);
    onCallSelect?.(call.id);
  };

  const activeCalls = Array.from(state.activeCalls.values());
  const recentCalls = state.completedCalls.slice(0, 5);

  return (
    <div className="space-y-4">
      {/* Stats Overview */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="border-primary/20 bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Active Calls</p>
                <p className="text-2xl font-bold font-mono text-primary">{activeCalls.length}</p>
              </div>
              <div className="p-2 rounded-full bg-primary/10">
                <Phone className="h-5 w-5 text-primary" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Total Calls</p>
                <p className="text-2xl font-bold font-mono text-primary">{state.totalCalls}</p>
              </div>
              <div className="p-2 rounded-full bg-primary/10">
                <Users className="h-5 w-5 text-primary" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Failed Calls</p>
                <p className={`text-2xl font-bold font-mono ${state.failedCalls > 0 ? 'text-destructive' : 'text-primary'}`}>
                  {state.failedCalls}
                </p>
              </div>
              <div className={`p-2 rounded-full ${state.failedCalls > 0 ? 'bg-destructive/10' : 'bg-primary/10'}`}>
                <AlertTriangle className={`h-5 w-5 ${state.failedCalls > 0 ? 'text-destructive' : 'text-primary'}`} />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Avg Duration</p>
                <p className="text-2xl font-bold font-mono text-primary">
                  {formatDuration(state.avgCallDuration)}
                </p>
              </div>
              <div className="p-2 rounded-full bg-primary/10">
                <Clock className="h-5 w-5 text-primary" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Live Call Flow */}
      <div className="grid grid-cols-2 gap-4">
        {/* Active Calls */}
        <Card className="border-primary/20 bg-card/50 cyber-glow">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-primary">
              <Activity className="h-5 w-5 animate-pulse-alert" />
              Active Calls
              {activeCalls.length > 0 && (
                <Badge variant="outline" className="border-primary text-primary animate-pulse-alert">
                  {activeCalls.length}
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 max-h-[300px] overflow-auto">
            {activeCalls.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Phone className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No active calls</p>
              </div>
            ) : (
              activeCalls.map((call) => {
                const StateIcon = getCallStateIcon(call.state);
                const isSelected = selectedCall === call.id;
                
                return (
                  <Button
                    key={call.id}
                    variant="ghost"
                    className={`w-full justify-start p-3 h-auto ${
                      isSelected ? 'bg-primary/10 border border-primary/30' : 'hover:bg-secondary/50'
                    }`}
                    onClick={() => handleCallClick(call)}
                  >
                    <div className="flex items-center justify-between w-full">
                      <div className="flex items-center gap-3">
                        <StateIcon className={`h-4 w-4 ${getCallStateColor(call.state)}`} />
                        <div className="text-left">
                          <div className="font-mono text-sm">
                            {call.fromNumber || call.fromIP} → {call.toNumber || call.toIP}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {formatTime(call.startTime)} • {call.state.toUpperCase()}
                          </div>
                        </div>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {call.state === 'answered' && formatDuration(Date.now() - call.startTime.getTime())}
                      </div>
                    </div>
                  </Button>
                );
              })
            )}
          </CardContent>
        </Card>

        {/* Recent Completed Calls */}
        <Card className="border-primary/20 bg-card/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-primary">
              <Clock className="h-5 w-5" />
              Recent Calls
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 max-h-[300px] overflow-auto">
            {recentCalls.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <PhoneOff className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No recent calls</p>
              </div>
            ) : (
              recentCalls.map((call) => {
                const StateIcon = getCallStateIcon(call.state);
                
                return (
                  <div
                    key={call.id}
                    className={`p-3 rounded-lg border ${
                      call.failed ? 'border-destructive/30 bg-destructive/5' : 'border-border/30 bg-secondary/20'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <StateIcon className={`h-4 w-4 ${getCallStateColor(call.state)}`} />
                        <div>
                          <div className="font-mono text-sm">
                            {call.fromNumber || call.fromIP} → {call.toNumber || call.toIP}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {formatTime(call.startTime)} • {formatDuration(call.duration)}
                            {call.failed && call.failureReason && (
                              <span className="text-destructive ml-2">• {call.failureReason}</span>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
