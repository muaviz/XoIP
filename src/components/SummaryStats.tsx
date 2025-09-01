import { TrendingUp, Shield, AlertTriangle, Phone, Network, Activity } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

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
    if (trend === 'up') return '↑';
    if (trend === 'down') return '↓';
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

export const SummaryStats = () => {
  return (
    <div className="grid grid-cols-6 gap-4">
      <StatCard
        title="Total Packets"
        value="24,537"
        change="+12% vs last hour"
        icon={Network}
        trend="up"
      />
      
      <StatCard
        title="Active Calls"
        value="47"
        change="3 new calls"
        icon={Phone}
        trend="up"
      />
      
      <StatCard
        title="Encrypted Traffic"
        value="68%"
        change="+5% secure"
        icon={Shield}
        trend="up"
      />
      
      <StatCard
        title="Alerts"
        value="12"
        change="4 critical"
        icon={AlertTriangle}
        alert={true}
      />
      
      <StatCard
        title="Bandwidth"
        value="1.2 Mbps"
        change="Normal load"
        icon={Activity}
        trend="neutral"
      />
      
      <StatCard
        title="Success Rate"
        value="94.2%"
        change="-2.1% today"
        icon={TrendingUp}
        trend="down"
      />
    </div>
  );
};
