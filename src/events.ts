import { EventEmitter } from 'events';

export const auditEmitter = new EventEmitter();

export function emitStep(type: string, text: string) {
  auditEmitter.emit('step', { type, text, timestamp: new Date().toISOString() });
}

export function emitProgress(status: string) {
  auditEmitter.emit('status', { status, timestamp: new Date().toISOString() });
}
