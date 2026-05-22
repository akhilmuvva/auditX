/**
 * AuditX — Wallet Connection Library (EIP-1193 / MetaMask)
 * Zero external wallet SDK — uses window.ethereum directly.
 */

export interface WalletInfo {
  address: string;
  chainId: number;
  ensName?: string;
  balance?: string;
}

export async function connectWallet(): Promise<WalletInfo> {
  const eth = (window as any).ethereum;
  if (!eth) {
    throw new Error('No Web3 wallet detected. Please install MetaMask.');
  }

  const accounts: string[] = await eth.request({ method: 'eth_requestAccounts' });
  if (!accounts.length) throw new Error('No accounts returned from wallet.');

  const address = accounts[0];
  const chainIdHex: string = await eth.request({ method: 'eth_chainId' });
  const chainId = parseInt(chainIdHex, 16);

  // Try to get balance
  let balance: string | undefined;
  try {
    const balHex: string = await eth.request({
      method: 'eth_getBalance',
      params: [address, 'latest'],
    });
    const balBigInt = BigInt(balHex);
    const balEth = Number(balBigInt) / 1e18;
    balance = balEth.toFixed(4);
  } catch {}

  return { address, chainId, balance };
}

export async function getConnectedAccounts(): Promise<string[]> {
  const eth = (window as any).ethereum;
  if (!eth) return [];
  try {
    return await eth.request({ method: 'eth_accounts' });
  } catch {
    return [];
  }
}

export function onAccountsChanged(cb: (accounts: string[]) => void) {
  (window as any).ethereum?.on('accountsChanged', cb);
  return () => (window as any).ethereum?.removeListener('accountsChanged', cb);
}

export function onChainChanged(cb: (chainId: string) => void) {
  (window as any).ethereum?.on('chainChange', cb);
  return () => (window as any).ethereum?.removeListener('chainChange', cb);
}

export function truncateAddress(address: string) {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

export function chainName(chainId: number): string {
  const names: Record<number, string> = {
    1: 'Ethereum',
    5: 'Goerli',
    11155111: 'Sepolia',
    137: 'Polygon',
    80001: 'Mumbai',
    8453: 'Base',
    84532: 'Base Sepolia',
    42161: 'Arbitrum',
    10: 'Optimism',
  };
  return names[chainId] || `Chain ${chainId}`;
}

export function isMetaMaskInstalled(): boolean {
  return !!(window as any).ethereum?.isMetaMask;
}
