import { useEffect, useState } from 'react';
import './App.css';
import { RpcProvider } from 'starknet';
import { disconnect } from '@starknet-io/get-starknet';
import { getStarknet, type StarknetWindowObject } from '@starknet-io/get-starknet-core';
import { TransactionFetcher, type SwapProtocolConfig, type SwapWithPrice } from './services/TransactionFetcher';

const STARKNET_SNAP_ID = 'npm:@consensys/starknet-snap';

function App() {
  const [connectedAddress, setConnectedAddress] = useState('');
  const [manualAddress, setManualAddress] = useState('');
  const [walletLabel, setWalletLabel] = useState('');
  const [walletLoading, setWalletLoading] = useState(false);
  const [snapEnabling, setSnapEnabling] = useState(false);
  const [walletError, setWalletError] = useState<string | null>(null);

  const [bridgeLoading, setBridgeLoading] = useState(false);
  const [bridgeError, setBridgeError] = useState<string | null>(null);
  const [bridgeNotice, setBridgeNotice] = useState<string | null>(null);
  const [bridgeRows, setBridgeRows] = useState<SwapWithPrice[]>([]);

  const [jediswapContract, setJediswapContract] = useState(import.meta.env.VITE_JEDISWAP_CONTRACT ?? '');
  const [ekuboContract, setEkuboContract] = useState(import.meta.env.VITE_EKUBO_CONTRACT ?? '');
  const [rpcUrl, setRpcUrl] = useState(import.meta.env.VITE_RPC_URL ?? 'https://starknet-mainnet.public.blastapi.io/rpc/v0_8');
  const [pragmaBaseUrl, setPragmaBaseUrl] = useState(import.meta.env.VITE_PRAGMA_BASE_URL ?? '');
  const [pragmaPair, setPragmaPair] = useState(import.meta.env.VITE_PRAGMA_PAIR ?? 'ETH/USD');
  const [lookbackBlocks, setLookbackBlocks] = useState('1200');

  const [walletDiagnostics, setWalletDiagnostics] = useState({
    lastAttempt: 'idle',
    hasEthereumProvider: false,
    hasInjectedSnapProvider: false,
    authorizedWalletIds: [] as string[],
    availableWalletIds: [] as string[],
    lastError: null as string | null,
  });

  useEffect(() => {
    void refreshWalletDiagnostics('startup');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!connectedAddress) return;
    void fetchRecentTransactions('auto');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connectedAddress]);

  const activeAddress = connectedAddress.trim();

  const shortHex = (value: string | null | undefined, start = 8, end = 6): string => {
    if (!value) return '-';
    if (value.length <= start + end + 2) return value;
    return `${value.slice(0, start + 2)}…${value.slice(-end)}`;
  };

  const formatTimestamp = (value: number | null): string => {
    if (value === null) return '-';
    return `${value} (${new Date(value * 1000).toISOString()})`;
  };

  const buildProtocolConfigs = (): SwapProtocolConfig[] => {
    const configs: SwapProtocolConfig[] = [
      ...(jediswapContract.trim()
        ? [{ name: 'Jediswap', contractAddress: jediswapContract.trim(), eventNames: ['Swap'] }]
        : []),
      ...(ekuboContract.trim()
        ? [{ name: 'Ekubo', contractAddress: ekuboContract.trim(), eventNames: ['Swap'] }]
        : []),
    ];

    if (!configs.length) {
      throw new Error('Set at least one protocol contract address (Jediswap or Ekubo).');
    }
    return configs;
  };

  const createFetcher = (protocolConfigs: SwapProtocolConfig[]) => {
    const baseUrl = pragmaBaseUrl.trim();
    if (!baseUrl) throw new Error('Pragma base URL is required.');
    const nodeUrl = rpcUrl.trim();
    if (!nodeUrl) throw new Error('RPC URL is required.');

    const provider = new RpcProvider({
      nodeUrl,
    });

    return new TransactionFetcher(provider, protocolConfigs, {
      baseUrl,
      queryParams: pragmaPair.trim() ? { pair: pragmaPair.trim() } : undefined,
      apiKey: import.meta.env.VITE_PRAGMA_API_KEY,
    });
  };

  const refreshWalletDiagnostics = async (lastAttempt: string, error?: unknown) => {
    const ethereum = getEthereumProvider();
    const injected = getInjectedMetaMaskSnap();
    const starknet = getStarknet();

    let authorizedWalletIds: string[] = [];
    let availableWalletIds: string[] = [];
    let lastError: string | null = error instanceof Error ? error.message : error ? String(error) : null;

    try {
      await starknet.discoverVirtualWallets();
      const authorized = await starknet.getAuthorizedWallets({ sort: ['metamask', 'argentX', 'braavos'] });
      const available = await starknet.getAvailableWallets({ sort: ['metamask', 'argentX', 'braavos'] });
      authorizedWalletIds = authorized.map((wallet) => `${wallet.name} (${wallet.id})`);
      availableWalletIds = available.map((wallet) => `${wallet.name} (${wallet.id})`);
    } catch (diagError) {
      if (!lastError) {
        lastError = diagError instanceof Error ? diagError.message : String(diagError);
      }
    }

    setWalletDiagnostics({
      lastAttempt,
      hasEthereumProvider: Boolean(ethereum?.request),
      hasInjectedSnapProvider: Boolean(injected?.request),
      authorizedWalletIds,
      availableWalletIds,
      lastError,
    });
  };

  const enableMetaMaskSnap = async () => {
    try {
      setSnapEnabling(true);
      setWalletError(null);
      const enabled = await requestStarknetSnapFromMetaMask();
      if (!enabled) {
        setWalletError('Could not enable Starknet Snap via MetaMask. Check Snaps permission and install status.');
      }
      await refreshWalletDiagnostics('enable-snap');
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : String(error));
      await refreshWalletDiagnostics('enable-snap-error', error);
    } finally {
      setSnapEnabling(false);
    }
  };

  const connectWallet = async () => {
    try {
      setWalletLoading(true);
      setWalletError(null);
      setBridgeError(null);
      setBridgeNotice(null);
      await refreshWalletDiagnostics('connect-start');
      await requestStarknetSnapFromMetaMask();

      const attemptErrors: string[] = [];
      let wallet: StarknetWindowObject | null = null;

      try {
        wallet = await connectUsingInjectedMetaMaskSnap();
      } catch (error) {
        attemptErrors.push(`injected-snap: ${error instanceof Error ? error.message : String(error)}`);
      }

      if (!wallet) {
        try {
          wallet = await connectUsingCoreWalletFlow();
        } catch (error) {
          attemptErrors.push(`core-wallet-flow: ${error instanceof Error ? error.message : String(error)}`);
        }
      }

      if (!wallet) {
        throw new Error(
          `Could not connect through Starknet Snap provider. ${attemptErrors.length ? `Details: ${attemptErrors.join(' | ')}` : 'No wallet provider returned an account.'
          }`
        );
      }

      const accounts = await requestAccountsWithFallbacks(wallet);
      if (!accounts || accounts.length === 0) {
        throw new Error('Wallet connected but no Starknet accounts were returned.');
      }

      setConnectedAddress(accounts[0]);
      setWalletLabel(wallet.name);
      await refreshWalletDiagnostics('connect-success');
    } catch (error) {
      const raw = error instanceof Error ? error.message : String(error);
      if (isSnapChunkLoadError(raw)) {
        setWalletError(
          'MetaMask Starknet Snap is failing to load remote chunks from snaps.consensys.io. ' +
          'Use the manual Starknet address fallback below to continue fetching transactions now.'
        );
      } else {
        setWalletError(raw);
      }
      await refreshWalletDiagnostics('connect-error', error);
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
      await refreshWalletDiagnostics('disconnect');
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

      if (!activeAddress) throw new Error('Connect wallet first or set a manual Starknet address.');
      const protocolConfigs = buildProtocolConfigs();
      const fetcher = createFetcher(protocolConfigs);
      const lookback = Number(lookbackBlocks.trim());
      const lookbackSafe = Number.isFinite(lookback) && lookback > 0 ? Math.floor(lookback) : 1200;

      const rows = await fetcher.fetchRecentSwapsWithPragma({
        userAddress: activeAddress,
        lookbackBlocks: lookbackSafe,
      });

      setBridgeRows(rows);
      setBridgeNotice(`Loaded ${rows.length} recent swaps.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const hint = message.includes('Failed to fetch')
        ? ' Check RPC URL/CORS/network access (for mainnet use a public Starknet RPC endpoint).'
        : '';
      if (mode === 'auto') {
        setBridgeNotice(`Wallet connected, but auto-fetch failed: ${message}.${hint}`);
      } else {
        setBridgeError(`${message}.${hint}`);
      }
    } finally {
      setBridgeLoading(false);
    }
  };

  return (
    <div className="simple-shell">
      <header className="simple-header">
        <p className="eyebrow">Scaffold Garaga</p>
        <h1>Starknet Wallet + Transaction Fetch</h1>
        <p>Minimal flow: connect Starknet wallet via MetaMask Snap, then fetch recent swaps and Pragma signatures.</p>
      </header>

      <section className="card">
        <div className="wallet-row">
          <div>
            {activeAddress
              ? `Connected: ${walletLabel || 'Wallet'} (${shortHex(connectedAddress)})`
              : 'No wallet connected.'}
          </div>
          {!activeAddress ? (
            <div className="wallet-actions">
              <button className="secondary-button" onClick={enableMetaMaskSnap} disabled={snapEnabling || walletLoading}>
                {snapEnabling ? 'Enabling…' : 'Enable Starknet Snap'}
              </button>
              <button className="primary-button" onClick={connectWallet} disabled={snapEnabling || walletLoading}>
                {walletLoading ? 'Connecting…' : 'Connect Wallet'}
              </button>
            </div>
          ) : (
            <button className="secondary-button" onClick={disconnectWallet} disabled={walletLoading}>
              Disconnect
            </button>
          )}
        </div>

        <div className="diagnostics">
          <div><strong>Diagnostics:</strong> {walletDiagnostics.lastAttempt}</div>
          <div>Ethereum provider: {walletDiagnostics.hasEthereumProvider ? 'yes' : 'no'}</div>
          <div>Injected Starknet Snap: {walletDiagnostics.hasInjectedSnapProvider ? 'yes' : 'no'}</div>
          <div>Authorized wallets: {walletDiagnostics.authorizedWalletIds.join(', ') || 'none'}</div>
          <div>Available wallets: {walletDiagnostics.availableWalletIds.join(', ') || 'none'}</div>
          {walletDiagnostics.lastError && <div>Last error: {walletDiagnostics.lastError}</div>}
        </div>

        {walletError && <div className="error-message">{walletError}</div>}

        {!activeAddress && (
          <div className="manual-address-row">
            <div className="field">
              <label htmlFor="manual-address">Manual Starknet address fallback</label>
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
                const value = manualAddress.trim();
                if (!isLikelyStarknetAddress(value)) {
                  setWalletError('Enter a valid Starknet address (0x...) to use manual mode.');
                  return;
                }
                setWalletError(null);
                setConnectedAddress(value);
                setWalletLabel('Manual Address');
              }}
            >
              Use Address
            </button>
          </div>
        )}
      </section>

      <section className="card">
        <h2>Transaction Fetch Config</h2>
        <div className="config-grid">
          <div className="field">
            <label htmlFor="jediswap-contract">Jediswap contract</label>
            <input id="jediswap-contract" value={jediswapContract} onChange={(e) => setJediswapContract(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="ekubo-contract">Ekubo contract</label>
            <input id="ekubo-contract" value={ekuboContract} onChange={(e) => setEkuboContract(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="pragma-url">Pragma API base URL</label>
            <input id="pragma-url" value={pragmaBaseUrl} onChange={(e) => setPragmaBaseUrl(e.target.value)} placeholder="https://..." />
          </div>
          <div className="field">
            <label htmlFor="rpc-url">Starknet RPC URL</label>
            <input id="rpc-url" value={rpcUrl} onChange={(e) => setRpcUrl(e.target.value)} placeholder="https://.../rpc/v0_8" />
          </div>
          <div className="field">
            <label htmlFor="pragma-pair">Pragma pair</label>
            <input id="pragma-pair" value={pragmaPair} onChange={(e) => setPragmaPair(e.target.value)} placeholder="ETH/USD" />
          </div>
          <div className="field">
            <label htmlFor="lookback">Lookback blocks</label>
            <input id="lookback" value={lookbackBlocks} onChange={(e) => setLookbackBlocks(e.target.value)} />
          </div>
        </div>
        <button
          className="primary-button"
          disabled={!activeAddress || bridgeLoading}
          onClick={() => {
            void fetchRecentTransactions('manual');
          }}
        >
          {bridgeLoading ? 'Fetching…' : 'Fetch Recent Transactions'}
        </button>

        {bridgeNotice && <p className="note">{bridgeNotice}</p>}
        {bridgeError && <div className="error-message">{bridgeError}</div>}
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
  const injected = (window as unknown as { starknet_metamask?: StarknetWindowObject }).starknet_metamask;
  return injected ?? null;
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

  throw new Error(`wallet_requestAccounts failed for all payload variants: ${errors.join(' | ')}`);
}

function isSnapChunkLoadError(message: string): boolean {
  const lower = message.toLowerCase();
  return lower.includes('loading chunk') && lower.includes('snaps.consensys.io');
}

function isLikelyStarknetAddress(value: string): boolean {
  const trimmed = value.trim().toLowerCase();
  return /^0x[0-9a-f]{20,66}$/.test(trimmed);
}
