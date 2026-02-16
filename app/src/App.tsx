import { useEffect, useMemo, useState } from 'react';
import './App.css';
import { RpcProvider } from 'starknet';
import { disconnect } from '@starknet-io/get-starknet';
import { getStarknet, type StarknetWindowObject } from '@starknet-io/get-starknet-core';
import { TransactionFetcher, type SwapProtocolConfig, type SwapWithPrice } from './services/TransactionFetcher';

const STARKNET_SNAP_ID = 'npm:@consensys/starknet-snap';

type AutoFetchConfig = {
  rpcUrl: string;
  pragmaBaseUrl: string;
  pragmaPair?: string;
  lookbackBlocks: number;
  protocols: SwapProtocolConfig[];
};

function App() {
  const [connectedAddress, setConnectedAddress] = useState('');
  const [manualAddress, setManualAddress] = useState('');
  const [walletLabel, setWalletLabel] = useState('');
  const [walletLoading, setWalletLoading] = useState(false);
  const [walletError, setWalletError] = useState<string | null>(null);

  const [bridgeLoading, setBridgeLoading] = useState(false);
  const [bridgeError, setBridgeError] = useState<string | null>(null);
  const [bridgeNotice, setBridgeNotice] = useState<string | null>(null);
  const [bridgeRows, setBridgeRows] = useState<SwapWithPrice[]>([]);

  const autoFetchConfig = useMemo(buildAutoFetchConfig, []);
  const activeAddress = connectedAddress.trim();

  useEffect(() => {
    if (!activeAddress) return;
    void fetchRecentTransactions('auto');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeAddress]);

  const shortHex = (value: string | null | undefined, start = 8, end = 6): string => {
    if (!value) return '-';
    if (value.length <= start + end + 2) return value;
    return `${value.slice(0, start + 2)}…${value.slice(-end)}`;
  };

  const formatTimestamp = (value: number | null): string => {
    if (value === null) return '-';
    return `${value} (${new Date(value * 1000).toISOString()})`;
  };

  const createFetcher = () => {
    const provider = new RpcProvider({ nodeUrl: autoFetchConfig.rpcUrl });
    return new TransactionFetcher(provider, autoFetchConfig.protocols, {
      baseUrl: autoFetchConfig.pragmaBaseUrl,
      queryParams: autoFetchConfig.pragmaPair ? { pair: autoFetchConfig.pragmaPair } : undefined,
      apiKey: import.meta.env.VITE_PRAGMA_API_KEY,
    });
  };

  const connectWallet = async () => {
    try {
      setWalletLoading(true);
      setWalletError(null);
      setBridgeError(null);
      setBridgeNotice(null);
      let wallet: StarknetWindowObject | null = null;
      const injectedProvider = getInjectedMetaMaskSnap();

      if (injectedProvider) {
        // Prefer direct injected provider to avoid remote wallet loader chunk failures.
        const accounts = await requestAccountsWithFallbacks(injectedProvider);
        if (!accounts.length) {
          throw new Error('Injected Starknet provider returned no accounts.');
        }
        setConnectedAddress(accounts[0]);
        setWalletLabel(injectedProvider.name || 'MetaMask Starknet');
        return;
      }

      await requestStarknetSnapFromMetaMask();

      const injectedAfterRequest = getInjectedMetaMaskSnap();
      if (injectedAfterRequest) {
        const accounts = await requestAccountsWithFallbacks(injectedAfterRequest);
        if (!accounts.length) {
          throw new Error('Starknet Snap was detected but no accounts were returned.');
        }
        setConnectedAddress(accounts[0]);
        setWalletLabel(injectedAfterRequest.name || 'MetaMask Starknet');
        return;
      }

      wallet = await connectUsingCoreWalletFlow();

      if (!wallet) {
        throw new Error('Could not detect a Starknet wallet provider. Open MetaMask Snap tab and refresh this page, then retry.');
      }

      const accounts = await requestAccountsWithFallbacks(wallet);
      if (!accounts || accounts.length === 0) {
        throw new Error('Wallet connected but no Starknet accounts were returned.');
      }

      setConnectedAddress(accounts[0]);
      setWalletLabel(wallet.name);
    } catch (error) {
      const raw = error instanceof Error ? error.message : String(error);
      setWalletError(isSnapChunkLoadError(raw)
        ? 'MetaMask Starknet Snap failed to load required remote assets. Check snaps.consensys.io access, then retry. You can also use manual address fallback below.'
        : raw);
    } finally {
      setWalletLoading(false);
    }
  };

  const disconnectWallet = async () => {
    try {
      setWalletLoading(true);
      await disconnect({ clearLastWallet: true });
      setConnectedAddress('');
      setWalletLabel('');
      setBridgeRows([]);
      setWalletError(null);
      setBridgeError(null);
      setBridgeNotice(null);
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : String(error));
    } finally {
      setWalletLoading(false);
    }
  };

  const fetchRecentTransactions = async (mode: 'auto' | 'manual') => {
    try {
      setBridgeLoading(true);
      setBridgeError(null);
      setBridgeNotice(null);
      if (mode === 'manual') {
        setBridgeRows([]);
      }

      if (!activeAddress) throw new Error('Connect wallet first.');
      if (!autoFetchConfig.protocols.length) throw new Error('Backend config missing: no protocol contracts configured.');
      if (!autoFetchConfig.rpcUrl) throw new Error('Backend config missing: RPC URL.');

      const fetcher = createFetcher();
      const rows = await fetcher.fetchRecentSwapsWithPragma({
        userAddress: activeAddress,
        lookbackBlocks: autoFetchConfig.lookbackBlocks,
      });

      setBridgeRows(rows);
      setBridgeNotice(`Loaded ${rows.length} recent swaps automatically.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (mode === 'auto') {
        setBridgeNotice(`Auto-fetch failed: ${message}`);
      } else {
        setBridgeError(message);
      }
    } finally {
      setBridgeLoading(false);
    }
  };

  return (
    <div className="simple-shell">
      <header className="simple-header">
        <p className="eyebrow">Scaffold Garaga</p>
        <h1>Connect Wallet to Load Recent Transactions</h1>
        <p>Transaction fetch configuration is managed on backend/env. Connect wallet to load recent swaps automatically.</p>
      </header>

      <section className="card">
        <div className="wallet-row">
          <div>
            {activeAddress
              ? `Connected: ${walletLabel || 'Wallet'} (${shortHex(activeAddress)})`
              : 'No wallet connected.'}
          </div>
          {!activeAddress ? (
            <button className="primary-button" onClick={connectWallet} disabled={walletLoading}>
              {walletLoading ? 'Connecting…' : 'Connect Wallet'}
            </button>
          ) : (
            <div className="wallet-actions">
              <button
                className="secondary-button"
                disabled={bridgeLoading}
                onClick={() => {
                  void fetchRecentTransactions('manual');
                }}
              >
                {bridgeLoading ? 'Refreshing…' : 'Refresh'}
              </button>
              <button className="secondary-button" onClick={disconnectWallet} disabled={walletLoading}>
                Disconnect
              </button>
            </div>
          )}
        </div>

        {walletError && <div className="error-message">{walletError}</div>}
        {bridgeNotice && <p className="note">{bridgeNotice}</p>}
        {bridgeError && <div className="error-message">{bridgeError}</div>}

        {!activeAddress && (
          <div className="manual-address-row">
            <div className="field">
              <label htmlFor="manual-address">Manual Starknet address (fallback)</label>
              <input
                id="manual-address"
                value={manualAddress}
                onChange={(e) => setManualAddress(e.target.value)}
                placeholder="0x..."
              />
            </div>
            <button
              className="secondary-button"
              onClick={() => {
                const candidate = manualAddress.trim();
                if (!isLikelyStarknetAddress(candidate)) {
                  setWalletError('Enter a valid Starknet address (0x...) for manual mode.');
                  return;
                }
                setWalletError(null);
                setConnectedAddress(candidate);
                setWalletLabel('Manual Address');
              }}
            >
              Use Address
            </button>
          </div>
        )}
      </section>

      <section className="card">
        <h2>Recent Transactions</h2>
        <p className="note">{bridgeRows.length} rows</p>
        {bridgeRows.length === 0 ? (
          <p className="note">No rows yet.</p>
        ) : (
          <div className="table-wrap">
            <table className="tx-table">
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Event</th>
                  <th>Tx</th>
                  <th>Block</th>
                  <th>Timestamp</th>
                  <th>Amount In</th>
                  <th>Amount Out</th>
                  <th>Pragma Signature</th>
                </tr>
              </thead>
              <tbody>
                {bridgeRows.map((row, idx) => (
                  <tr key={`${row.txHash}-${row.eventName}-${idx}`}>
                    <td>{row.protocol}</td>
                    <td>{row.eventName}</td>
                    <td title={row.txHash}>{shortHex(row.txHash)}</td>
                    <td>{row.blockNumber ?? '-'}</td>
                    <td title={row.timestamp === null ? '' : String(row.timestamp)}>{formatTimestamp(row.timestamp)}</td>
                    <td title={row.amountInRaw ?? ''}>{shortHex(row.amountInRaw, 10, 8)}</td>
                    <td title={row.amountOutRaw ?? ''}>{shortHex(row.amountOutRaw, 10, 8)}</td>
                    <td title={row.pragma?.signature ?? ''}>{shortHex(row.pragma?.signature, 10, 8)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

export default App;

async function connectUsingCoreWalletFlow(): Promise<StarknetWindowObject | null> {
  const starknet = getStarknet();
  await starknet.discoverVirtualWallets();

  const authorized = await starknet.getAuthorizedWallets({ sort: ['metamask', 'argentX', 'braavos'] });
  const authorizedWallet = pickPreferredWallet(authorized);
  if (authorizedWallet) {
    try {
      const enabled = await starknet.enable(authorizedWallet);
      await requestAccountsWithFallbacks(enabled);
      return enabled;
    } catch (error) {
      throw new Error(`failed to enable authorized wallet (${authorizedWallet.name}): ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  const available = await starknet.getAvailableWallets({ sort: ['metamask', 'argentX', 'braavos'] });
  const availableWallet = pickPreferredWallet(available);
  if (!availableWallet) return null;
  const enabled = await starknet.enable(availableWallet);
  await requestAccountsWithFallbacks(enabled);
  return enabled;
}

async function connectUsingInjectedMetaMaskSnap(): Promise<StarknetWindowObject | null> {
  const injected = getInjectedMetaMaskSnap();
  if (!injected?.request) {
    return null;
  }

  const accounts = await requestAccountsWithFallbacks(injected);
  if (Array.isArray(accounts) && accounts.length > 0) {
    return injected;
  }
  return null;
}

function normalizeWalletId(value: unknown): string {
  return String(value ?? '').trim().toLowerCase();
}

function pickPreferredWallet(wallets: StarknetWindowObject[]): StarknetWindowObject | null {
  if (!wallets.length) return null;

  const metamask = wallets.find((wallet) => {
    const id = normalizeWalletId(wallet.id);
    const name = normalizeWalletId(wallet.name);
    return id.includes('metamask') || name.includes('metamask');
  });

  return metamask ?? wallets[0];
}

function getInjectedMetaMaskSnap(): StarknetWindowObject | null {
  if (typeof window === 'undefined') return null;
  const w = window as unknown as Record<string, unknown>;

  const directCandidates = [
    w.starknet_metamask,
    w.starknet,
  ];
  for (const candidate of directCandidates) {
    if (isStarknetProvider(candidate)) {
      return candidate;
    }
  }

  for (const [key, value] of Object.entries(w)) {
    if (!key.toLowerCase().includes('starknet')) continue;
    if (isStarknetProvider(value)) {
      return value;
    }
  }

  return null;
}

function getEthereumProvider():
  | { request?: (args: { method: string; params?: unknown[] | Record<string, unknown> }) => Promise<unknown> }
  | null {
  if (typeof window === 'undefined') return null;
  const ethereum = (window as unknown as {
    ethereum?: { request?: (args: { method: string; params?: unknown[] | Record<string, unknown> }) => Promise<unknown> };
  }).ethereum;
  return ethereum ?? null;
}

async function requestStarknetSnapFromMetaMask(): Promise<boolean> {
  if (getInjectedMetaMaskSnap()?.request) {
    return true;
  }

  const ethereum = getEthereumProvider();
  if (!ethereum?.request) return false;

  try {
    await ethereum.request({
      method: 'wallet_requestSnaps',
      params: {
        [STARKNET_SNAP_ID]: {},
      },
    });
  } catch (error) {
    console.warn('wallet_requestSnaps failed or was rejected.', error);
  }

  // Give MetaMask a brief moment to inject starknet_metamask into the page context.
  for (let i = 0; i < 8; i += 1) {
    if (getInjectedMetaMaskSnap()?.request) return true;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  return Boolean(getInjectedMetaMaskSnap()?.request);
}

async function requestAccountsWithFallbacks(wallet: StarknetWindowObject): Promise<string[]> {
  const attempts: Array<() => Promise<string[]>> = [
    async () => wallet.request({ type: 'wallet_requestAccounts' }),
    async () => wallet.request({ type: 'wallet_requestAccounts', params: { silent_mode: false } }),
    async () => wallet.request({ type: 'wallet_requestAccounts', params: { api_version: '1.0.0' } }),
    async () => wallet.request({ type: 'wallet_requestAccounts', params: { api_version: '1.0.0', silent_mode: false } }),
    async () => wallet.request({ type: 'wallet_requestAccounts', params: { api_version: '0.7.0' } }),
    async () => wallet.request({ type: 'wallet_requestAccounts', params: { api_version: '0.7.0', silent_mode: false } }),
  ];

  const errors: string[] = [];
  for (const attempt of attempts) {
    try {
      const accounts = await attempt();
      if (Array.isArray(accounts) && accounts.length > 0) {
        return accounts;
      }
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }

  const legacyAccounts = await tryLegacyEnable(wallet);
  if (legacyAccounts.length > 0) {
    return legacyAccounts;
  }

  throw new Error(`wallet_requestAccounts failed for all payload variants: ${errors.join(' | ')}`);
}

function isSnapChunkLoadError(message: string): boolean {
  const lower = message.toLowerCase();
  return lower.includes('loading chunk') && lower.includes('snaps.consensys.io');
}

function isLikelyStarknetAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]{20,66}$/.test(value.trim());
}

function isStarknetProvider(value: unknown): value is StarknetWindowObject {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  return typeof v.request === 'function' && typeof v.name === 'string';
}

async function tryLegacyEnable(wallet: StarknetWindowObject): Promise<string[]> {
  const maybeLegacy = wallet as unknown as { enable?: () => Promise<string[] | void> };
  if (typeof maybeLegacy.enable !== 'function') return [];

  try {
    const accounts = await maybeLegacy.enable();
    return Array.isArray(accounts) ? accounts : [];
  } catch (error) {
    console.warn('Legacy wallet.enable() fallback failed.', error);
    return [];
  }
}

function buildAutoFetchConfig(): AutoFetchConfig {
  const lookbackRaw = Number(import.meta.env.VITE_LOOKBACK_BLOCKS ?? '1200');
  const lookbackBlocks = Number.isFinite(lookbackRaw) && lookbackRaw > 0 ? Math.floor(lookbackRaw) : 1200;

  const protocols: SwapProtocolConfig[] = [
    ...(import.meta.env.VITE_JEDISWAP_CONTRACT
      ? [{ name: 'Jediswap', contractAddress: String(import.meta.env.VITE_JEDISWAP_CONTRACT), eventNames: ['Swap'] }]
      : []),
    ...(import.meta.env.VITE_EKUBO_CONTRACT
      ? [{ name: 'Ekubo', contractAddress: String(import.meta.env.VITE_EKUBO_CONTRACT), eventNames: ['Swap'] }]
      : []),
  ];

  return {
    rpcUrl: String(import.meta.env.VITE_RPC_URL ?? 'https://starknet-mainnet.public.blastapi.io/rpc/v0_8'),
    pragmaBaseUrl: String(import.meta.env.VITE_PRAGMA_BASE_URL ?? ''),
    pragmaPair: String(import.meta.env.VITE_PRAGMA_PAIR ?? 'ETH/USD'),
    lookbackBlocks,
    protocols,
  };
}
