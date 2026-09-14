import { TrendingUp, Shield, AlertTriangle, Phone, Network, Activity } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import type { DissectedPacket } from "@/lib/pcapParser";
import type { CallFlowAnalyzerState } from "@/lib/callFlowAnalyzer";

interface StatCardProps {
  title: string;
  value: string;
  change?: string;
  icon: React.ComponentType<{ className?: string }>;
  trend?: 'up' | 'down' | 'neutral';
  alert?: boolean;
}

const StatCard = ({ title, value, change, icon: Icon, trend = 'neutral', alert = false }: StatCardProps) => {
  const getTrendColor = () => {
    if (alert) return 'text-destructive';
    switch (trend) {
      case 'up': return 'text-success';
      case 'down': return 'text-destructive';
      default: return 'text-muted-foreground';
    }
  };

  const getTrendIcon = () => {
    if (trend === 'up') return '↑ ';
    if (trend === 'down') return '↓ ';
    return '';
  };

  return (
    <Card className={`border ${alert ? 'border-destructive/30 alert-glow' : 'border-primary/20'} bg-card/50 hover:cyber-glow transition-all`}>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground uppercase tracking-wider">{title}</p>
            <p className={`text-2xl font-bold font-mono ${alert ? 'text-destructive' : 'text-primary'}`}>
              {value}
            </p>
            {change && (
              <p className={`text-xs ${getTrendColor()} flex items-center gap-1`}>
                <span>{getTrendIcon()}</span>
                {change}
              </p>
            )}
          </div>
          <div className={`p-2 rounded-full ${alert ? 'bg-destructive/10' : 'bg-primary/10'}`}>
            <Icon className={`h-5 w-5 ${alert ? 'text-destructive' : 'text-primary'}`} />
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

interface SummaryStatsProps {
  packets: DissectedPacket[];
  analyzerState: CallFlowAnalyzerState;
}

export const SummaryStats = ({ packets, analyzerState }: SummaryStatsProps) => {
  const totalPackets = packets.length;
  const activeCallsCount = analyzerState.activeCalls.size;
  const encryptedCount = packets.filter(p => p.encrypted).length;
  const encryptedPercent = totalPackets > 0 ? Math.round((encryptedCount / totalPackets) * 100) : 0;
  
  const alertsCount = packets.filter(p => p.suspicious).length;

  const totalBytes = packets.reduce((acc, p) => acc + (p.size || 0), 0);
  const formattedBytes = totalBytes > 1024 * 1024
    ? `${(totalBytes / (1024 * 1024)).toFixed(2)} MB`
    : `${(totalBytes / 1024).toFixed(1)} KB`;

  const totalCalls = analyzerState.totalCalls;
  const failedCalls = analyzerState.failedCalls;
  const successRate = totalCalls > 0
    ? `${Math.max(0, Math.round(((totalCalls - failedCalls) / totalCalls) * 100))}%`
    : '100%';

  return (
    <div className="grid grid-cols-6 gap-4">
      <StatCard
        title="Total Packets"
        value={totalPackets.toLocaleString()}
        change={totalPackets > 0 ? `${packets.filter(p => p.protocol === 'SIP').length} SIP / ${packets.filter(p => p.protocol === 'RTP').length} RTP` : 'Awaiting traffic'}
        icon={Network}
        trend={totalPackets > 0 ? 'up' : 'neutral'}
      />
      
      <StatCard
        title="Active Calls"
        value={activeCallsCount.toString()}
        change={`${analyzerState.completedCalls.length} completed`}
        icon={Phone}
        trend={activeCallsCount > 0 ? 'up' : 'neutral'}
      />
      
      <StatCard
        title="Encrypted Traffic"
        value={`${encryptedPercent}%`}
        change={`${encryptedCount} TLS/SRTP pkts`}
        icon={Shield}
        trend={encryptedPercent > 50 ? 'up' : 'neutral'}
      />
      
      <StatCard
        title="Alerts & Issues"
        value={alertsCount.toString()}
        change={alertsCount > 0 ? `${alertsCount} anomalies flagged` : 'Zero issues'}
        icon={AlertTriangle}
        alert={alertsCount > 0}
      />
      
      <StatCard
        title="Capture Volume"
        value={formattedBytes}
        change={`${totalBytes.toLocaleString()} bytes wire`}
        icon={Activity}
        trend="neutral"
      />
      
      <StatCard
        title="Success Rate"
        value={successRate}
        change={failedCalls > 0 ? `${failedCalls} failed calls` : 'All sessions healthy'}
        icon={TrendingUp}
        trend={failedCalls > 0 ? 'down' : 'up'}
      />
    </div>
  );
};
