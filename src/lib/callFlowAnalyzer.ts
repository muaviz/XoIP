import type { DissectedPacket } from "./pcapParser";

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
  userAgent?: string;
  rtpPacketsCount?: number;
  rtpPayloadType?: number;
  audioBytesList?: Uint8Array[];
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

  reset() {
    this.state = {
      activeCalls: new Map(),
      completedCalls: [],
      totalCalls: 0,
      failedCalls: 0,
      avgCallDuration: 0
    };
    this.notifyListeners();
  }

  processPacket(packet: DissectedPacket) {
    if (!packet) return;

    if (packet.protocol === 'SIP') {
      this.processSipPacket(packet);
    } else if (packet.protocol === 'RTP') {
      this.processRtpPacket(packet);
    }
  }

  private processSipPacket(packet: DissectedPacket) {
    const rawCallId = packet.metadata?.['Call-ID'] || '';
    const callId = rawCallId || this.generateCallId(packet);
    const method = (packet.method || '').toUpperCase();
    const status = (packet.status || '').toUpperCase();

    if (method.includes('INVITE')) {
      this.handleInvite(callId, packet);
    } else if (method.includes('ACK')) {
      this.handleAck(callId, packet);
    } else if (method.includes('BYE')) {
      this.handleBye(callId, packet);
    } else if (method.includes('CANCEL')) {
      this.handleCancel(callId, packet);
    } else if (packet.method.startsWith('SIP ') || status.includes('OK') || status.includes('RINGING') || status.includes('TRYING') || status.includes('BUSY') || status.match(/^[1-6]\d\d/)) {
      this.handleSipResponse(callId, packet);
    } else {
      // General SIP request (OPTIONS, REGISTER, etc.)
      this.handleGenericSip(callId, packet);
    }

    this.notifyListeners();
  }

  private processRtpPacket(packet: DissectedPacket) {
    // Correlate RTP packet with active call sessions by matching IP endpoints
    for (const call of this.state.activeCalls.values()) {
      const matchEndpoints = (
        (call.fromIP === packet.sourceIP && call.toIP === packet.destIP) ||
        (call.fromIP === packet.destIP && call.toIP === packet.sourceIP)
      );

      if (matchEndpoints) {
        call.packets.push(packet.id);
        call.lastActivity = new Date(packet.rawTimestampMs || packet.timestamp);
        call.rtpPacketsCount = (call.rtpPacketsCount || 0) + 1;

        if (packet.rtpData?.audioPayload && packet.rtpData.audioPayload.length > 0) {
          if (!call.audioBytesList) call.audioBytesList = [];
          if (call.audioBytesList.length < 5000) { // Limit stored chunks to prevent memory explosion
            call.audioBytesList.push(packet.rtpData.audioPayload);
          }
          if (call.rtpPayloadType === undefined) {
            call.rtpPayloadType = packet.rtpData.payloadType;
          }
        }
        break;
      }
    }
  }

  private handleInvite(callId: string, packet: DissectedPacket) {
    const existingCall = this.state.activeCalls.get(callId);
    const ts = new Date(packet.rawTimestampMs || packet.timestamp);
    const codec = packet.metadata?.['SDP Codecs'] || packet.metadata?.['Content-Type'];
    const userAgent = packet.metadata?.['User-Agent'];

    if (!existingCall) {
      const newCall: CallSession = {
        id: callId,
        callId,
        fromIP: packet.sourceIP,
        toIP: packet.destIP,
        fromNumber: this.extractNumber(packet.metadata?.['From']),
        toNumber: this.extractNumber(packet.metadata?.['To']),
        state: 'initiated',
        startTime: ts,
        lastActivity: ts,
        sipMethod: packet.method,
        packets: [packet.id],
        failed: false,
        codec,
        userAgent,
        rtpPacketsCount: 0
      };

      this.state.activeCalls.set(callId, newCall);
      this.state.totalCalls++;
    } else {
      existingCall.packets.push(packet.id);
      existingCall.lastActivity = ts;
      if (codec && !existingCall.codec) existingCall.codec = codec;
      if (userAgent && !existingCall.userAgent) existingCall.userAgent = userAgent;
    }
  }

  private handleSipResponse(callId: string, packet: DissectedPacket) {
    let call = this.state.activeCalls.get(callId);
    const ts = new Date(packet.rawTimestampMs || packet.timestamp);
    const statusText = packet.status || '';

    // If call wasn't tracked by Call-ID yet, see if any call matches endpoints
    if (!call) {
      for (const c of this.state.activeCalls.values()) {
        if ((c.fromIP === packet.destIP && c.toIP === packet.sourceIP) || (c.fromIP === packet.sourceIP && c.toIP === packet.destIP)) {
          call = c;
          break;
        }
      }
    }

    if (!call) return;

    call.packets.push(packet.id);
    call.lastActivity = ts;
    call.sipStatus = statusText;

    if (packet.metadata?.['SDP Codecs'] && !call.codec) {
      call.codec = packet.metadata['SDP Codecs'];
    }

    if (statusText.includes('100')) {
      call.state = 'trying';
    } else if (statusText.includes('180') || statusText.includes('183')) {
      call.state = 'ringing';
    } else if (statusText.includes('200')) {
      call.state = 'answered';
    } else if (statusText.match(/^[4-6]\d\d/) || statusText.toLowerCase().includes('busy') || statusText.toLowerCase().includes('forbidden') || statusText.toLowerCase().includes('not found')) {
      call.state = 'failed';
      call.failed = true;
      call.failureReason = statusText;
      this.moveToCompleted(call);
    }
  }

  private handleAck(callId: string, packet: DissectedPacket) {
    const call = this.state.activeCalls.get(callId);
    if (!call) return;

    call.packets.push(packet.id);
    call.lastActivity = new Date(packet.rawTimestampMs || packet.timestamp);
    call.state = 'answered';
  }

  private handleBye(callId: string, packet: DissectedPacket) {
    const call = this.state.activeCalls.get(callId);
    if (!call) return;

    const ts = new Date(packet.rawTimestampMs || packet.timestamp);
    call.packets.push(packet.id);
    call.endTime = ts;
    call.duration = Math.max(0, call.endTime.getTime() - call.startTime.getTime());
    call.state = 'ended';

    this.moveToCompleted(call);
  }

  private handleCancel(callId: string, packet: DissectedPacket) {
    const call = this.state.activeCalls.get(callId);
    if (!call) return;

    const ts = new Date(packet.rawTimestampMs || packet.timestamp);
    call.packets.push(packet.id);
    call.endTime = ts;
    call.state = 'failed';
    call.failed = true;
    call.failureReason = 'Cancelled by caller';

    this.moveToCompleted(call);
  }

  private handleGenericSip(callId: string, packet: DissectedPacket) {
    const call = this.state.activeCalls.get(callId);
    if (call) {
      call.packets.push(packet.id);
      call.lastActivity = new Date(packet.rawTimestampMs || packet.timestamp);
    }
  }

  private moveToCompleted(call: CallSession) {
    this.state.activeCalls.delete(call.callId);
    // Avoid duplicates in completedCalls
    if (!this.state.completedCalls.some(c => c.callId === call.callId)) {
      this.state.completedCalls.unshift(call);
    }

    if (call.failed) {
      this.state.failedCalls++;
    }

    // Keep only last 100 completed calls
    if (this.state.completedCalls.length > 100) {
      this.state.completedCalls = this.state.completedCalls.slice(0, 100);
    }

    this.updateAverageCallDuration();
  }

  private updateAverageCallDuration() {
    const completedWithDuration = this.state.completedCalls.filter(c => c.duration && !c.failed);
    if (completedWithDuration.length > 0) {
      const totalDuration = completedWithDuration.reduce((sum, call) => sum + (call.duration || 0), 0);
      this.state.avgCallDuration = Math.round(totalDuration / completedWithDuration.length);
    }
  }

  private generateCallId(packet: DissectedPacket): string {
    return `${packet.sourceIP}-${packet.destIP}-${packet.rawTimestampMs || Date.now()}`;
  }

  private extractNumber(field?: string): string | undefined {
    if (!field) return undefined;
    // Format: "Alice" <sip:alice@192.168.1.1> or <sip:+1234567890@domain.com;tag=xyz>
    const match = field.match(/sip:([^@>;\s]+)/i);
    if (match) return match[1];
    const userMatch = field.match(/"([^"]+)"/);
    if (userMatch) return userMatch[1];
    return field.substring(0, 20);
  }

  subscribe(listener: (state: CallFlowAnalyzerState) => void) {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  private notifyListeners() {
    this.listeners.forEach(listener => listener({
      ...this.state,
      activeCalls: new Map(this.state.activeCalls),
      completedCalls: [...this.state.completedCalls]
    }));
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
        call.failureReason = 'Session Inactivity Timeout';
        call.endTime = call.lastActivity;
        this.moveToCompleted(call);
      }
    }

    this.notifyListeners();
  }
}
