// State for pending jobs: jobId -> { score -> count, reports -> [] }
const jobConsensusState: Record<string, {
    scores: Record<string, number>;
    reports: any[];
    resolved: boolean;
}> = {};

/**
 * Handles incoming results from the network and attempts to reach consensus.
 * Consensus is reached when `threshold` number of agents report the exact same score.
 */
export function handleConsensusResult(data: any, threshold: number = 2) {
    const { jobId, agentAddress, resultSummary } = data;
    const { score } = resultSummary;

    if (!jobConsensusState[jobId]) {
        jobConsensusState[jobId] = {
            scores: {},
            reports: [],
            resolved: false
        };
    }

    const state = jobConsensusState[jobId];

    if (state.resolved) {
        return; // Consensus already reached
    }

    state.reports.push(data);
    state.scores[score] = (state.scores[score] || 0) + 1;

    console.log(`[Consensus] Job ${jobId} - Agent ${agentAddress} voted Score: ${score}. Total votes for ${score}: ${state.scores[score]}/${threshold}`);

    // Check if consensus is reached
    if (state.scores[score] >= threshold) {
        state.resolved = true;
        console.log(`\n========================================`);
        console.log(`[Consensus] 🟢 REACHED for Job: ${jobId}`);
        console.log(`[Consensus] Final Agreed Score: ${score}`);
        console.log(`========================================\n`);
        
        // In a real implementation, this would trigger the on-chain submission or finalization logic
        finalizeConsensus(jobId, score, state.reports);
    }
}

function finalizeConsensus(jobId: string, finalScore: string, allReports: any[]) {
    // E.g., select one of the IPFS CIDs to submit to AuditRegistry, or aggregate them
    const validReport = allReports.find(r => r.resultSummary.score === finalScore);
    if (validReport) {
        console.log(`[Consensus] Proceeding to on-chain with CID: ${validReport.resultSummary.ipfsCid}`);
        // Integration point with AuditRegistry.submitAudit
    }
}
