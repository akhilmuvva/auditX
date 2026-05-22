import { ApolloClient, InMemoryCache, gql } from '@apollo/client/core/index.js';
import fetch from 'node-fetch';

const GRAPH_URL = process.env.SUBGRAPH_URL || 'https://api.studio.thegraph.com/query/auditx/v1';

export const apolloClient = new ApolloClient({
  uri: GRAPH_URL,
  cache: new InMemoryCache(),
  // @ts-ignore
  fetch: fetch as any
});

export async function queryAuditsByContract(contractHash: string) {
  const QUERY = gql`
    query GetAudits($contractHash: String!) {
      auditSubmitteds(where: { contractHash: $contractHash }) {
        id
        auditor
        ipfsCID
        cvssScore
        riskLevel
        blockTimestamp
      }
    }
  `;

  try {
    const { data } = await apolloClient.query({
      query: QUERY,
      variables: { contractHash }
    });
    return data.auditSubmitteds;
  } catch (error: any) {
    console.error('[Storage] TheGraph query failed:', error.message);
    return [];
  }
}
