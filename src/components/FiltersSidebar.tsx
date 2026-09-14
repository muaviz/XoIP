import { useMemo } from "react";
import { Filter, X, Shield, AlertTriangle, Phone, Network } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import type { DissectedPacket } from "@/lib/pcapParser";

export interface FilterState {
  protocols: string[];
  encryption: string[];
  alertTypes: string[];
  callTypes: string[];
}

interface FiltersSidebarProps {
  filters: FilterState;
  onFiltersChange: (filters: FilterState) => void;
  packets?: DissectedPacket[];
}

export const FiltersSidebar = ({ filters, onFiltersChange, packets = [] }: FiltersSidebarProps) => {
  const activeFilters = Object.values(filters).reduce((total, arr) => total + arr.length, 0);

  // Dynamically calculate packet counts per category from actual packets
  const counts = useMemo(() => {
    const protoCounts: Record<string, number> = {
      sip: 0,
      rtp: 0,
      rtcp: 0,
      tcp: 0,
      udp: 0,
      tls: 0
    };
    const encCounts: Record<string, number> = {
      encrypted: 0,
      unencrypted: 0
    };
    const alertCounts: Record<string, number> = {
      'failed-calls': 0,
      'malformed': 0,
      'suspicious-ip': 0,
      'auth-failure': 0,
      'unusual-ports': 0
    };
    const callCounts: Record<string, number> = {
      incoming: 0,
      outgoing: 0,
      internal: 0,
      conference: 0
    };

    for (const p of packets) {
      // Protocols
      const proto = p.protocol.toLowerCase();
      if (proto in protoCounts) {
        protoCounts[proto]++;
      }
      if (p.encrypted && proto !== 'tls') {
        protoCounts.tls++;
      }

      // Encryption
      if (p.encrypted) {
        encCounts.encrypted++;
      } else {
        encCounts.unencrypted++;
      }

      // Alerts
      if (p.alertType && p.alertType in alertCounts) {
        alertCounts[p.alertType]++;
      }

      // Call Types
      if (p.callType && p.callType in callCounts) {
        callCounts[p.callType]++;
      }
    }

    return { protoCounts, encCounts, alertCounts, callCounts };
  }, [packets]);

  const protocolOptions = [
    { id: 'sip', label: 'SIP', count: counts.protoCounts.sip },
    { id: 'rtp', label: 'RTP', count: counts.protoCounts.rtp },
    { id: 'rtcp', label: 'RTCP', count: counts.protoCounts.rtcp },
    { id: 'tcp', label: 'TCP', count: counts.protoCounts.tcp },
    { id: 'udp', label: 'UDP', count: counts.protoCounts.udp },
    { id: 'tls', label: 'TLS', count: counts.protoCounts.tls }
  ];

  const encryptionOptions = [
    { id: 'encrypted', label: 'Encrypted', count: counts.encCounts.encrypted, icon: Shield },
    { id: 'unencrypted', label: 'Unencrypted', count: counts.encCounts.unencrypted, icon: Network }
  ];

  const alertOptions = [
    { id: 'failed-calls', label: 'Failed Calls', count: counts.alertCounts['failed-calls'], severity: 'high' },
    { id: 'malformed', label: 'Malformed Headers', count: counts.alertCounts['malformed'], severity: 'medium' },
    { id: 'suspicious-ip', label: 'Suspicious IPs', count: counts.alertCounts['suspicious-ip'], severity: 'high' },
    { id: 'auth-failure', label: 'Auth Failures', count: counts.alertCounts['auth-failure'], severity: 'medium' },
    { id: 'unusual-ports', label: 'Unusual Ports', count: counts.alertCounts['unusual-ports'], severity: 'low' }
  ];

  const callTypeOptions = [
    { id: 'incoming', label: 'Incoming Calls', count: counts.callCounts.incoming },
    { id: 'outgoing', label: 'Outgoing Calls', count: counts.callCounts.outgoing },
    { id: 'internal', label: 'Internal Calls', count: counts.callCounts.internal },
    { id: 'conference', label: 'Conference Calls', count: counts.callCounts.conference }
  ];

  const handleFilterChange = (category: keyof FilterState, value: string, checked: boolean) => {
    const updatedFilters = {
      ...filters,
      [category]: checked
        ? [...filters[category], value]
        : filters[category].filter(item => item !== value)
    };
    
    onFiltersChange(updatedFilters);
  };

  const clearAllFilters = () => {
    onFiltersChange({
      protocols: [],
      encryption: [],
      alertTypes: [],
      callTypes: []
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return 'text-destructive';
      case 'medium': return 'text-warning';
      case 'low': return 'text-muted-foreground';
      default: return 'text-muted-foreground';
    }
  };

  return (
    <Card className="h-full border border-primary/20 bg-card/50">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-primary">
            <Filter className="h-5 w-5" />
            Filters
            {activeFilters > 0 && (
              <Badge variant="outline" className="ml-2 border-primary text-primary">
                {activeFilters}
              </Badge>
            )}
          </CardTitle>
          {activeFilters > 0 && (
            <Button
              variant="ghost"
              size="sm"
              onClick={clearAllFilters}
              className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
            >
              <X className="h-3 w-3" />
            </Button>
          )}
        </div>
      </CardHeader>
      
      <CardContent className="space-y-6 max-h-[calc(100vh-200px)] overflow-auto">
        {/* Protocol Filters */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Network className="h-4 w-4 text-primary" />
            Protocol
          </h3>
          <div className="space-y-2">
            {protocolOptions.map((protocol) => (
              <div key={protocol.id} className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id={protocol.id}
                    checked={filters.protocols.includes(protocol.id)}
                    onCheckedChange={(checked) => 
                      handleFilterChange('protocols', protocol.id, checked as boolean)
                    }
                  />
                  <label
                    htmlFor={protocol.id}
                    className="text-sm font-medium leading-none cursor-pointer peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
                  >
                    {protocol.label}
                  </label>
                </div>
                <Badge variant="secondary" className="text-xs font-mono">
                  {protocol.count}
                </Badge>
              </div>
            ))}
          </div>
        </div>

        <Separator className="bg-primary/10" />

        {/* Encryption Status */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            Encryption
          </h3>
          <div className="space-y-2">
            {encryptionOptions.map((option) => (
              <div key={option.id} className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id={option.id}
                    checked={filters.encryption.includes(option.id)}
                    onCheckedChange={(checked) => 
                      handleFilterChange('encryption', option.id, checked as boolean)
                    }
                  />
                  <label
                    htmlFor={option.id}
                    className="text-sm font-medium leading-none cursor-pointer peer-disabled:cursor-not-allowed peer-disabled:opacity-70 flex items-center gap-2"
                  >
                    <option.icon className="h-3 w-3" />
                    {option.label}
                  </label>
                </div>
                <Badge variant="secondary" className="text-xs font-mono">
                  {option.count}
                </Badge>
              </div>
            ))}
          </div>
        </div>

        <Separator className="bg-primary/10" />

        {/* Alert Types */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-destructive" />
            Alerts & Issues
          </h3>
          <div className="space-y-2">
            {alertOptions.map((alert) => (
              <div key={alert.id} className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id={alert.id}
                    checked={filters.alertTypes.includes(alert.id)}
                    onCheckedChange={(checked) => 
                      handleFilterChange('alertTypes', alert.id, checked as boolean)
                    }
                  />
                  <label
                    htmlFor={alert.id}
                    className={`text-sm font-medium leading-none cursor-pointer peer-disabled:cursor-not-allowed peer-disabled:opacity-70 ${alert.count > 0 ? getSeverityColor(alert.severity) : 'text-muted-foreground'}`}
                  >
                    {alert.label}
                  </label>
                </div>
                <Badge 
                  variant="secondary" 
                  className={`text-xs font-mono ${alert.count > 0 ? getSeverityColor(alert.severity) : ''}`}
                >
                  {alert.count}
                </Badge>
              </div>
            ))}
          </div>
        </div>

        <Separator className="bg-primary/10" />

        {/* Call Types */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Phone className="h-4 w-4 text-primary" />
            Call Types
          </h3>
          <div className="space-y-2">
            {callTypeOptions.map((callType) => (
              <div key={callType.id} className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id={callType.id}
                    checked={filters.callTypes.includes(callType.id)}
                    onCheckedChange={(checked) => 
                      handleFilterChange('callTypes', callType.id, checked as boolean)
                    }
                  />
                  <label
                    htmlFor={callType.id}
                    className="text-sm font-medium leading-none cursor-pointer peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
                  >
                    {callType.label}
                  </label>
                </div>
                <Badge variant="secondary" className="text-xs font-mono">
                  {callType.count}
                </Badge>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
