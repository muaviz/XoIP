export interface CallSession {
  id: string;
  callId: string;
  fromIP: string;
  toIP: string;
  fromNumber?: string;
  toNumber?: string;
  state: 'initiated' | 'trying' | 'ringing' | 'answered' | 'ended' | 'failed';
  startTime: Date;
  endTime?: Date;
  duration?: number;
  lastActivity: Date;
  sipMethod: string;
  sipStatus?: string;
  packets: string[];
  codec?: string;
  failed: boolean;
  failureReason?: string;
}

export interface CallFlowAnalyzerState {
  activeCalls: Map<string, CallSession>;
  completedCalls: CallSession[];
  totalCalls: number;
  failedCalls: number;
  avgCallDuration: number;
}

export class CallFlowAnalyzer {
  private state: CallFlowAnalyzerState = {
    activeCalls: new Map(),
    completedCalls: [],
    totalCalls: 0,
    failedCalls: 0,
    avgCallDuration: 0
  };

  private listeners: ((state: CallFlowAnalyzerState) => void)[] = [];

  processPacket(packet: any) {
    if (packet.protocol !== 'SIP') return;

    const callId = packet.metadata['Call-ID'] || this.generateCallId(packet);
    
    switch (packet.method) {
      case 'INVITE':
        this.handleInvite(callId, packet);
        break;
      case 'ACK':
        this.handleAck(callId, packet);
        break;
      case 'BYE':
        this.handleBye(callId, packet);
        break;
      case 'CANCEL':
        this.handleCancel(callId, packet);
        break;
      default:
        this.handleSipResponse(callId, packet);
    }

    this.notifyListeners();
  }

  private handleInvite(callId: string, packet: any) {
    const existingCall = this.state.activeCalls.get(callId);
    
    if (!existingCall) {
      const newCall: CallSession = {
        id: callId,
        callId,
        fromIP: packet.sourceIP,
        toIP: packet.destIP,
        fromNumber: this.extractNumber(packet.metadata['From']),
        toNumber: this.extractNumber(packet.metadata['To']),
        state: 'initiated',
        startTime: new Date(packet.timestamp),
        lastActivity: new Date(packet.timestamp),
        sipMethod: packet.method,
        packets: [packet.id],
        failed: false
      };
      
      this.state.activeCalls.set(callId, newCall);
      this.state.totalCalls++;
    } else {
      existingCall.packets.push(packet.id);
      existingCall.lastActivity = new Date(packet.timestamp);
    }
  }

  private handleSipResponse(callId: string, packet: any) {
    const call = this.state.activeCalls.get(callId);
    if (!call) return;

    call.packets.push(packet.id);
    call.lastActivity = new Date(packet.timestamp);
    call.sipStatus = packet.status;

    if (packet.status.includes('100')) {
      call.state = 'trying';
    } else if (packet.status.includes('180') || packet.status.includes('183')) {
      call.state = 'ringing';
    } else if (packet.status.includes('200')) {
      call.state = 'answered';
    } else if (packet.status.startsWith('4') || packet.status.startsWith('5') || packet.status.startsWith('6')) {
      call.state = 'failed';
      call.failed = true;
      call.failureReason = packet.status;
      this.moveToCompleted(call);
    }
  }

  private handleAck(callId: string, packet: any) {
    const call = this.state.activeCalls.get(callId);
    if (!call) return;

    call.packets.push(packet.id);
    call.lastActivity = new Date(packet.timestamp);
    call.state = 'answered';
  }

  private handleBye(callId: string, packet: any) {
    const call = this.state.activeCalls.get(callId);
    if (!call) return;

    call.packets.push(packet.id);
    call.endTime = new Date(packet.timestamp);
    call.duration = call.endTime.getTime() - call.startTime.getTime();
    call.state = 'ended';
    
    this.moveToCompleted(call);
  }

  private handleCancel(callId: string, packet: any) {
    const call = this.state.activeCalls.get(callId);
    if (!call) return;

    call.packets.push(packet.id);
    call.endTime = new Date(packet.timestamp);
    call.state = 'failed';
    call.failed = true;
    call.failureReason = 'Cancelled';
    
    this.moveToCompleted(call);
  }

  private moveToCompleted(call: CallSession) {
    this.state.activeCalls.delete(call.callId);
    this.state.completedCalls.unshift(call);
    
    if (call.failed) {
      this.state.failedCalls++;
    }
    
    // Keep only last 50 completed calls
    if (this.state.completedCalls.length > 50) {
      this.state.completedCalls = this.state.completedCalls.slice(0, 50);
    }
    
    this.updateAverageCallDuration();
  }

  private updateAverageCallDuration() {
    const completedWithDuration = this.state.completedCalls.filter(c => c.duration && !c.failed);
    if (completedWithDuration.length > 0) {
      const totalDuration = completedWithDuration.reduce((sum, call) => sum + (call.duration || 0), 0);
      this.state.avgCallDuration = totalDuration / completedWithDuration.length;
    }
  }

  private generateCallId(packet: any): string {
    return `${packet.sourceIP}-${packet.destIP}-${Date.now()}`;
  }

  private extractNumber(field?: string): string | undefined {
    if (!field) return undefined;
    const match = field.match(/sip:([^@]+)@/);
    return match ? match[1] : undefined;
  }

  subscribe(listener: (state: CallFlowAnalyzerState) => void) {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  private notifyListeners() {
    this.listeners.forEach(listener => listener({ ...this.state }));
  }

  getState(): CallFlowAnalyzerState {
    return { ...this.state };
  }

  cleanup() {
    // Remove calls inactive for more than 5 minutes
    const cutoff = new Date(Date.now() - 5 * 60 * 1000);
    
    for (const [callId, call] of this.state.activeCalls.entries()) {
      if (call.lastActivity < cutoff) {
        call.state = 'failed';
        call.failed = true;
        call.failureReason = 'Timeout';
        call.endTime = call.lastActivity;
        this.moveToCompleted(call);
      }
    }
    
    this.notifyListeners();
  }
}
