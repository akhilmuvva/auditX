import { createLibp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { gossipsub } from '@chainsafe/libp2p-gossipsub';
import { identify } from '@libp2p/identify';

/**
 * Creates and starts a libp2p node configured for the AuditX network.
 * @param listenPort Port to listen on for TCP connections
 * @returns The started libp2p node instance
 */
export async function createAgentNode(listenPort: number = 0) {
  const node = await createLibp2p({
    addresses: {
      listen: [`/ip4/0.0.0.0/tcp/${listenPort}`]
    },
    transports: [tcp() as any],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: {
      // @ts-ignore
      pubsub: gossipsub({ allowPublishToZeroTopicPeers: true }),
      identify: identify()
    }
  });

  await node.start();
  
  console.log('Libp2p Agent Node Started');
  node.getMultiaddrs().forEach((addr) => {
    console.log(`Listening on ${addr.toString()}`);
  });

  return node;
}
