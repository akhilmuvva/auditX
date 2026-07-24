import { createAgentNode } from './node.js';
import { runPipeline } from '../pipeline.js';
import { broadcastResult } from './jobQueue.js';

export class AuditAgent {
  public node: any;
  public address: string;

  constructor(address: string) {
    this.address = address;
  }

  async start(port: number = 0) {
    this.node = await createAgentNode(port);
    
    // Subscribe to audit job topic
    this.node.services.pubsub.subscribe('audit-jobs');
    
    this.node.services.pubsub.addEventListener('message', async (message: any) => {
      if (message.detail.topic === 'audit-jobs') {
        const job = JSON.parse(new TextDecoder().decode(message.detail.data));
        console.log(`[Agent ${this.address}] Received job for ${job.targetFile}`);
        await this.handleJob(job);
      }
    });

    console.log(`[Agent ${this.address}] Listening for jobs...`);
  }

  async handleJob(job: any) {
    try {
      console.log(`[Agent ${this.address}] Running pipeline for ${job.targetFile}...`);
      
      const opts = {
        ai: true,
        ipfs: true,
        eas: job.eas || false,
        mint: job.mint || undefined,
        mythril: job.mythril || false
      };

      const result = await runPipeline(job.targetFile, opts);
      
      // Broadcast the result to peers for consensus
      await broadcastResult(this.node, job.jobId, result, this.address);
      
      console.log(`[Agent ${this.address}] Job ${job.jobId} completed and broadcasted.`);
    } catch (error: any) {
      console.error(`[Agent ${this.address}] Failed job ${job.jobId}:`, error.message);
    }
  }

  async stop() {
    if (this.node) {
      await this.node.stop();
      console.log(`[Agent ${this.address}] Stopped.`);
    }
  }
}
