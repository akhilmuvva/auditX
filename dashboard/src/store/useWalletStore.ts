import { create } from 'zustand';
import {
  connectWallet, getConnectedAccounts,
  onAccountsChanged, onChainChanged,
  truncateAddress, chainName, type WalletInfo,
} from '../lib/wallet';

interface WalletState {
  wallet: WalletInfo | null;
  connecting: boolean;
  error: string | null;

  connect: () => Promise<void>;
  disconnect: () => void;
  initListeners: () => () => void;

  // Derived
  isConnected: boolean;
  shortAddress: string;
  network: string;
}

export const useWalletStore = create<WalletState>((set, get) => ({
  wallet: null,
  connecting: false,
  error: null,

  get isConnected() { return !!get().wallet; },
  get shortAddress() {
    const w = get().wallet;
    return w ? truncateAddress(w.address) : '';
  },
  get network() {
    const w = get().wallet;
    return w ? chainName(w.chainId) : '';
  },

  connect: async () => {
    set({ connecting: true, error: null });
    try {
      const info = await connectWallet();
      set({ wallet: info, connecting: false });
    } catch (e: any) {
      set({ error: e.message, connecting: false });
    }
  },

  disconnect: () => {
    set({ wallet: null, error: null });
  },

  initListeners: () => {
    // Auto-detect already-connected wallet on page load
    getConnectedAccounts().then((accounts) => {
      if (accounts.length > 0) {
        connectWallet().then((info) => set({ wallet: info })).catch(() => {});
      }
    });

    const offAccounts = onAccountsChanged((accounts) => {
      if (accounts.length === 0) {
        set({ wallet: null });
      } else {
        connectWallet().then((info) => set({ wallet: info })).catch(() => {});
      }
    });

    const offChain = onChainChanged(() => {
      connectWallet().then((info) => set({ wallet: info })).catch(() => {});
    });

    return () => { offAccounts(); offChain(); };
  },
}));
