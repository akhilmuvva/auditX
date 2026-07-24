import { handleConsensusResult } from './consensus.js';

/**
 * Broadcasts an audit result to the libp2p network on the 'audit-results' topic
 */
export async function broadcastResult(node: any, jobId: string, result: any, agentAddress: string) {
  const payload = {
    jobId,
    agentAddress,
    resultSummary: {
      score: result.score,
      riskLevel: result.finalReport.riskLevel,
      ipfsCid: result.ipfsCid
    },
    timestamp: Date.now()
  };

  const encoded = new TextEncoder().encode(JSON.stringify(payload));
  
  await node.services.pubsub.publish('audit-results', encoded);
  console.log(`[JobQueue] Broadcasted result for job ${jobId}`);
}

/**
 * Subscribes to the audit-results topic and feeds them to the consensus engine
 */
export function listenForResults(node: any, consensusThreshold: number = 2) {
  node.services.pubsub.subscribe('audit-results');
  
  node.services.pubsub.addEventListener('message', (message: any) => {
    if (message.detail.topic === 'audit-results') {
      const data = JSON.parse(new TextDecoder().decode(message.detail.data));
      handleConsensusResult(data, consensusThreshold);
    }
  });

  console.log(`[JobQueue] Listening for audit results...`);
}

/**
 * Broadcasts a new job to the network
 */
export async function broadcastJob(node: any, targetFile: string, options: any = {}) {
  const jobId = 'job_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
  const payload = {
    jobId,
    targetFile,
    ...options
  };

  const encoded = new TextEncoder().encode(JSON.stringify(payload));
  await node.services.pubsub.publish('audit-jobs', encoded);
  
  console.log(`[JobQueue] Broadcasted new job ${jobId} for ${targetFile}`);
  return jobId;
}
