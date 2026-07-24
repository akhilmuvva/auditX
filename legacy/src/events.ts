import { EventEmitter } from 'events';
import type { StepId, StepStatus, StepEvent } from '@auditx/types';

export const auditEmitter = new EventEmitter();

// Strict format for Dashboard SSE and telemetry
export function emitStep(step: StepId, status: StepStatus, data?: any) {
  const event: StepEvent = {
    step,
    status,
    data,
    ts: Date.now()
  };
  auditEmitter.emit('step', event);
  console.log(JSON.stringify(event));
}

// Keeping a simpler progress emitter for UI convenience
export function emitProgress(status: string) {
  auditEmitter.emit('status', { status, timestamp: new Date().toISOString() });
}
