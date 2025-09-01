import { useState } from "react";
import { Filter, X, Shield, AlertTriangle, Phone, Network } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

interface FilterState {
  protocols: string[];
  encryption: string[];
  alertTypes: string[];
  callTypes: string[];
}

interface FiltersSidebarProps {
  filters: FilterState;
  onFiltersChange: (filters: FilterState) => void;
}

export const FiltersSidebar = ({ filters, onFiltersChange }: FiltersSidebarProps) => {
  const activeFilters = Object.values(filters).reduce((total, arr) => total + arr.length, 0);

  const protocolOptions = [
    { id: 'sip', label: 'SIP', count: 234 },
    { id: 'rtp', label: 'RTP', count: 156 },
    { id: 'rtcp', label: 'RTCP', count: 89 },
    { id: 'tcp', label: 'TCP', count: 45 },
    { id: 'udp', label: 'UDP', count: 298 },
    { id: 'tls', label: 'TLS', count: 67 }
  ];

  const encryptionOptions = [
    { id: 'encrypted', label: 'Encrypted', count: 134, icon: Shield },
    { id: 'unencrypted', label: 'Unencrypted', count: 89, icon: Network }
  ];

  const alertOptions = [
    { id: 'failed-calls', label: 'Failed Calls', count: 12, severity: 'high' },
    { id: 'malformed', label: 'Malformed Headers', count: 8, severity: 'medium' },
    { id: 'suspicious-ip', label: 'Suspicious IPs', count: 5, severity: 'high' },
    { id: 'auth-failure', label: 'Auth Failures', count: 15, severity: 'medium' },
    { id: 'unusual-ports', label: 'Unusual Ports', count: 3, severity: 'low' }
  ];

  const callTypeOptions = [
    { id: 'incoming', label: 'Incoming Calls', count: 45 },
    { id: 'outgoing', label: 'Outgoing Calls', count: 38 },
    { id: 'internal', label: 'Internal Calls', count: 67 },
    { id: 'conference', label: 'Conference Calls', count: 12 }
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
                    className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
                  >
                    {protocol.label}
                  </label>
                </div>
                <Badge variant="secondary" className="text-xs">
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
                    className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 flex items-center gap-2"
                  >
                    <option.icon className="h-3 w-3" />
                    {option.label}
                  </label>
                </div>
                <Badge variant="secondary" className="text-xs">
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
                    className={`text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 ${getSeverityColor(alert.severity)}`}
                  >
                    {alert.label}
                  </label>
                </div>
                <Badge 
                  variant="secondary" 
                  className={`text-xs ${getSeverityColor(alert.severity)}`}
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
                    className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
                  >
                    {callType.label}
                  </label>
                </div>
                <Badge variant="secondary" className="text-xs">
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
