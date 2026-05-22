import { createHelia } from 'helia';
import { unixfs } from '@helia/unixfs';

let heliaInstance: any = null;
let fsInstance: any = null;

export async function initIPFS() {
    if (!heliaInstance) {
        heliaInstance = await createHelia();
        fsInstance = unixfs(heliaInstance);
        console.log('[Storage] Helia node initialized');
    }
    return fsInstance;
}

export async function uploadToIPFS(data: any): Promise<string> {
    const fs = await initIPFS();
    const encoder = new TextEncoder();
    const bytes = encoder.encode(JSON.stringify(data));
    
    // Upload via Helia
    const cid = await fs.addBytes(bytes);
    console.log(`[Storage] Uploaded report to IPFS CID: ${cid.toString()}`);
    
    // In production, we'd also pin this to Web3.Storage or Pinata here.
    
    return cid.toString();
}

export async function fetchFromIPFS(cidStr: string): Promise<any> {
    const fs = await initIPFS();
    const { CID } = await import('multiformats/cid');
    const cid = CID.parse(cidStr);
    
    let text = '';
    const decoder = new TextDecoder();
    for await (const chunk of fs.cat(cid)) {
        text += decoder.decode(chunk, { stream: true });
    }
    
    return JSON.parse(text);
}
