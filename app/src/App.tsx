import React, { useEffect, useMemo, useState } from 'react';
import './App.css';
import { RpcProvider, Contract } from 'starknet';
import { disconnect } from '@starknet-io/get-starknet';
import { getStarknet, type StarknetWindowObject } from '@starknet-io/get-starknet-core';
import {
  TransactionFetcher,
  computeTradeRoiSummary,
  type SwapProtocolConfig,
  type SwapWithPrice,
  type TradeRoiSummary,
} from './services/TransactionFetcher';
import { generateRoiProof, verifyRoiProof, type RoiProofResult } from './services/ProofGenerator';
import { ProofState } from './types';

const STARKNET_SNAP_ID = 'npm:@consensys/starknet-snap';

type AutoFetchConfig = {
  rpcUrl: string;
  pragmaBaseUrl: string;
  pragmaPair?: string;
  pragmaTimeoutMs: number;
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

  const [roiSummary, setRoiSummary] = useState<TradeRoiSummary | null>(null);
  const [thresholdBps, setThresholdBps] = useState(500);
  const [proofState, setProofState] = useState<ProofState>(ProofState.Initial);
  const [proofProgress, setProofProgress] = useState('');
  const [proofError, setProofError] = useState<string | null>(null);
  const [proofResult, setProofResult] = useState<RoiProofResult | null>(null);
  const [localVerified, setLocalVerified] = useState<boolean | null>(null);

  const [onChainLoading, setOnChainLoading] = useState(false);
  const [onChainResult, setOnChainResult] = useState<boolean | null>(null);
  const [onChainError, setOnChainError] = useState<string | null>(null);
  const [onChainTxHash, setOnChainTxHash] = useState<string | null>(null);

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
      timeoutMs: autoFetchConfig.pragmaTimeoutMs,
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
        const accounts = await requestAccountsWithFallbacks(injectedProvider);
        if (!accounts.length) throw new Error('Injected Starknet provider returned no accounts.');
        setConnectedAddress(accounts[0]);
        setWalletLabel(injectedProvider.name || 'MetaMask Starknet');
        return;
      }

      await requestStarknetSnapFromMetaMask();

      const injectedAfterRequest = getInjectedMetaMaskSnap();
      if (injectedAfterRequest) {
        const accounts = await requestAccountsWithFallbacks(injectedAfterRequest);
        if (!accounts.length) throw new Error('Starknet Snap detected but no accounts returned.');
        setConnectedAddress(accounts[0]);
        setWalletLabel(injectedAfterRequest.name || 'MetaMask Starknet');
        return;
      }

      wallet = await connectUsingCoreWalletFlow();
      if (!wallet) throw new Error('No Starknet wallet detected. Open MetaMask Snap tab and refresh.');

      const accounts = await requestAccountsWithFallbacks(wallet);
      if (!accounts || accounts.length === 0) throw new Error('Wallet connected but no accounts returned.');

      setConnectedAddress(accounts[0]);
      setWalletLabel(wallet.name);
    } catch (error) {
      const raw = error instanceof Error ? error.message : String(error);
      setWalletError(isSnapChunkLoadError(raw)
        ? 'MetaMask Starknet Snap failed to load remote assets. Check snaps.consensys.io access, or use manual address below.'
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
      if (mode === 'manual') setBridgeRows([]);

      if (!activeAddress) throw new Error('Connect wallet first.');
      if (!autoFetchConfig.protocols.length) throw new Error('No protocol contracts configured.');
      if (!autoFetchConfig.rpcUrl) throw new Error('RPC URL not configured.');

      const fetcher = createFetcher();
      const rows = await fetcher.fetchRecentSwapsWithPragma({
        userAddress: activeAddress,
        lookbackBlocks: autoFetchConfig.lookbackBlocks,
      });

      setBridgeRows(rows);
      setBridgeNotice(`Loaded ${rows.length} recent swaps.`);

      const summary = computeTradeRoiSummary(rows);
      setRoiSummary(summary);

      setProofState(ProofState.Initial);
      setProofResult(null);
      setProofError(null);
      setLocalVerified(null);
      setOnChainResult(null);
      setOnChainError(null);
      setOnChainTxHash(null);
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

  const handleGenerateProof = async () => {
    if (!roiSummary?.proofInputHint) return;
    try {
      setProofState(ProofState.GeneratingWitness);
      setProofError(null);
      setProofResult(null);
      setLocalVerified(null);
      setOnChainResult(null);
      setOnChainError(null);
      setOnChainTxHash(null);

      const inputs = {
        totalIn: BigInt(roiSummary.proofInputHint.totalIn),
        totalOut: BigInt(roiSummary.proofInputHint.totalOut),
        thresholdBps,
        tradeCount: roiSummary.proofInputHint.tradeCount,
      };

      const result = await generateRoiProof(inputs, (stage) => {
        setProofProgress(stage);
        if (stage.toLowerCase().includes('proof')) setProofState(ProofState.GeneratingProof);
      });

      setProofResult(result);
      setProofState(ProofState.ProofVerified);

      try {
        const valid = await verifyRoiProof(result.proof, result.publicInputs);
        setLocalVerified(valid);
      } catch (verifyErr) {
        console.warn('Local verification failed:', verifyErr);
        setLocalVerified(null);
      }
    } catch (error) {
      setProofError(error instanceof Error ? error.message : String(error));
      setProofState(ProofState.Initial);
    }
  };

  const handleOnChainVerify = async () => {
    if (!proofResult) return;
    try {
      setOnChainLoading(true);
      setOnChainError(null);
      setOnChainResult(null);
      setOnChainTxHash(null);
      setProofState(ProofState.PreparingCalldata);

      const garaga = await import('garaga');
      const piBytes = publicInputsToBytes(proofResult.publicInputs);

      const vkResponse = await fetch(new URL('../assets/vk.bin', import.meta.url).href);
      if (!vkResponse.ok) throw new Error('Failed to load vk.bin');
      const vkBytes = new Uint8Array(await vkResponse.arrayBuffer());

      const calldata = garaga.getZKHonkCallData(proofResult.proof, piBytes, vkBytes);

      setProofState(ProofState.SendingTransaction);

      const verifierAddress = import.meta.env.VITE_VERIFIER_ADDRESS;
      if (!verifierAddress) throw new Error('VITE_VERIFIER_ADDRESS not set — deploy the verifier first.');

      const provider = new RpcProvider({ nodeUrl: autoFetchConfig.rpcUrl });
      const verifierAbi = [{
        name: 'verify_ultra_keccak_zk_honk_proof',
        type: 'function',
        inputs: [{ name: 'full_proof_with_hints', type: 'core::array::Span::<core::felt252>' }],
        outputs: [{ type: 'core::option::Option::<core::bool>' }],
        state_mutability: 'view',
      }];

      const verifierContract = new Contract({
        abi: verifierAbi,
        address: verifierAddress,
        providerOrAccount: provider,
      } as ConstructorParameters<typeof Contract>[0]);

      const result = await verifierContract.call('verify_ultra_keccak_zk_honk_proof', [calldata]);
      const verified = extractVerificationResult(result);
      setOnChainResult(verified);
      setOnChainTxHash(null);
      setProofState(ProofState.ProofVerified);
    } catch (error) {
      setOnChainError(error instanceof Error ? error.message : String(error));
      setProofState(ProofState.ProofVerified);
    } finally {
      setOnChainLoading(false);
    }
  };

  const roiBpsDisplay = roiSummary?.roiBps !== null && roiSummary?.roiBps !== undefined
    ? (roiSummary.roiBps / 100).toFixed(2)
    : null;

  const canProve = roiSummary?.proofInputHint !== null &&
    roiSummary?.proofInputHint !== undefined &&
    proofState !== ProofState.GeneratingWitness &&
    proofState !== ProofState.GeneratingProof;

  return (
    <div className="simple-shell">
      <header className="simple-header">
        <p className="eyebrow">Proof of Alpha</p>
        <h1>Connect Wallet to Load Recent Transactions</h1>
        <p>Connect your wallet to auto-fetch recent swaps and prove your trading ROI on-chain.</p>
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
                onClick={() => { void fetchRecentTransactions('manual'); }}
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
                  setWalletError('Enter a valid Starknet address (0x…).');
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

      {roiSummary && (
        <section className="card">
          <h2>ROI Summary</h2>
          <div className="roi-stats">
            <div className="roi-stat">
              <span className="roi-label">Trades</span>
              <span className="roi-value">{roiSummary.tradeCount}</span>
            </div>
            <div className="roi-stat">
              <span className="roi-label">Priced Trades</span>
              <span className="roi-value">{roiSummary.pricedTradeCount}</span>
            </div>
            <div className="roi-stat">
              <span className="roi-label">Winning Trades</span>
              <span className="roi-value">{roiSummary.winningTradeCount}</span>
            </div>
            <div className="roi-stat">
              <span className="roi-label">Win Rate</span>
              <span className="roi-value">
                {roiSummary.winRateBps !== null ? `${(roiSummary.winRateBps / 100).toFixed(1)}%` : '-'}
              </span>
            </div>
            <div className="roi-stat">
              <span className="roi-label">ROI</span>
              <span className={`roi-value ${roiBpsDisplay !== null ? (Number(roiBpsDisplay) >= 0 ? 'positive' : 'negative') : ''}`}>
                {roiBpsDisplay !== null ? `${roiBpsDisplay}%` : '-'}
              </span>
            </div>
            <div className="roi-stat">
              <span className="roi-label">Total In (raw)</span>
              <span className="roi-value mono">{shortHex(roiSummary.totalInRaw, 12, 8)}</span>
            </div>
            <div className="roi-stat">
              <span className="roi-label">Total Out (raw)</span>
              <span className="roi-value mono">{shortHex(roiSummary.totalOutRaw, 12, 8)}</span>
            </div>
          </div>
        </section>
      )}

      {roiSummary && roiSummary.proofInputHint && (
        <section className="card">
          <h2>Prove ROI Threshold</h2>
          <p className="note">
            Generate a ZK proof that your ROI exceeds a threshold without revealing exact amounts.
          </p>

          <div className="threshold-row">
            <div className="field">
              <label htmlFor="threshold-bps">Threshold (basis points)</label>
              <input
                id="threshold-bps"
                type="number"
                min={0}
                max={100000}
                step={100}
                value={thresholdBps}
                onChange={(e) => setThresholdBps(Math.max(0, Math.floor(Number(e.target.value) || 0)))}
              />
              <span className="field-hint">{(thresholdBps / 100).toFixed(2)}%</span>
            </div>
            <button
              className="primary-button"
              disabled={!canProve}
              onClick={() => { void handleGenerateProof(); }}
            >
              {proofState === ProofState.GeneratingWitness || proofState === ProofState.GeneratingProof
                ? proofProgress || 'Generating…'
                : 'Generate Proof'}
            </button>
          </div>

          {proofError && <div className="error-message">{proofError}</div>}

          {proofResult && (
            <div className="proof-result">
              <h3>Proof Generated</h3>
              <div className="proof-meta">
                <span>Time: {proofResult.elapsedMs}ms</span>
                <span>Size: {proofResult.proof.length} bytes</span>
                <span>Public inputs: {proofResult.publicInputs.length}</span>
                {localVerified !== null && (
                  <span className={localVerified ? 'positive' : 'negative'}>
                    Local verify: {localVerified ? 'VALID' : 'INVALID'}
                  </span>
                )}
              </div>
              <details>
                <summary>Raw proof (hex)</summary>
                <pre className="proof-hex">
                  {Array.from(proofResult.proof).map((b) => b.toString(16).padStart(2, '0')).join('')}
                </pre>
              </details>
              <details>
                <summary>Public inputs</summary>
                <pre className="proof-hex">
                  {proofResult.publicInputs.map((pi, i) => `[${i}] ${pi}`).join('\n')}
                </pre>
              </details>
            </div>
          )}
        </section>
      )}

      {proofResult && (
        <section className="card">
          <h2>On-Chain Verification</h2>
          <p className="note">
            Submit the proof to the deployed verifier contract on Starknet.
          </p>
          <button
            className="primary-button"
            disabled={onChainLoading}
            onClick={() => { void handleOnChainVerify(); }}
          >
            {onChainLoading ? 'Verifying on-chain…' : 'Verify On-Chain'}
          </button>

          {onChainError && <div className="error-message">{onChainError}</div>}

          {onChainResult !== null && (
            <div className={`on-chain-result ${onChainResult ? 'positive' : 'negative'}`}>
              On-chain verification: {onChainResult ? 'VALID' : 'INVALID'}
              {onChainTxHash && (
                <span className="mono"> (tx: {shortHex(onChainTxHash)})</span>
              )}
            </div>
          )}
        </section>
      )}
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
      throw new Error(`Failed to enable ${authorizedWallet.name}: ${error instanceof Error ? error.message : String(error)}`);
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
  if (!injected?.request) return null;

  const accounts = await requestAccountsWithFallbacks(injected);
  if (Array.isArray(accounts) && accounts.length > 0) return injected;
  return null;
}

function normalizeWalletId(value: unknown): string {
  return String(value ?? '').trim().toLowerCase();
}

function pickPreferredWallet(wallets: StarknetWindowObject[]): StarknetWindowObject | null {
  if (!wallets.length) return null;
  const metamask = wallets.find((w) => {
    const id = normalizeWalletId(w.id);
    const name = normalizeWalletId(w.name);
    return id.includes('metamask') || name.includes('metamask');
  });
  return metamask ?? wallets[0];
}

function getInjectedMetaMaskSnap(): StarknetWindowObject | null {
  if (typeof window === 'undefined') return null;
  const w = window as unknown as Record<string, unknown>;

  for (const candidate of [w.starknet_metamask, w.starknet]) {
    if (isStarknetProvider(candidate)) return candidate;
  }

  for (const [key, value] of Object.entries(w)) {
    if (!key.toLowerCase().includes('starknet')) continue;
    if (isStarknetProvider(value)) return value;
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
  if (getInjectedMetaMaskSnap()?.request) return true;

  const ethereum = getEthereumProvider();
  if (!ethereum?.request) return false;

  try {
    await ethereum.request({ method: 'wallet_requestSnaps', params: { [STARKNET_SNAP_ID]: {} } });
  } catch (error) {
    console.warn('wallet_requestSnaps failed or rejected', error);
  }

  // wait for MetaMask to inject starknet_metamask
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
      if (Array.isArray(accounts) && accounts.length > 0) return accounts;
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }

  const legacyAccounts = await tryLegacyEnable(wallet);
  if (legacyAccounts.length > 0) return legacyAccounts;

  throw new Error(`wallet_requestAccounts failed: ${errors.join(' | ')}`);
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
  } catch {
    return [];
  }
}

function buildAutoFetchConfig(): AutoFetchConfig {
  const lookbackRaw = Number(import.meta.env.VITE_LOOKBACK_BLOCKS ?? '32000');
  const lookbackBlocks = Number.isFinite(lookbackRaw) && lookbackRaw > 0 ? Math.floor(lookbackRaw) : 32000;
  const pragmaTimeoutRaw = Number(import.meta.env.VITE_PRAGMA_TIMEOUT_MS ?? '10000');
  const pragmaTimeoutMs = Number.isFinite(pragmaTimeoutRaw) && pragmaTimeoutRaw > 0 ? Math.floor(pragmaTimeoutRaw) : 10000;
  const ekuboEventKeys = parseCsvEnv(import.meta.env.VITE_EKUBO_EVENT_KEYS);

  const protocols: SwapProtocolConfig[] = [
    ...(import.meta.env.VITE_JEDISWAP_CONTRACT
      ? [{ name: 'Jediswap', contractAddress: String(import.meta.env.VITE_JEDISWAP_CONTRACT), eventNames: ['Swap'] }]
      : []),
    ...(import.meta.env.VITE_EKUBO_CONTRACT
      ? [{
        name: 'Ekubo',
        contractAddress: String(import.meta.env.VITE_EKUBO_CONTRACT),
        eventNames: ['Swap'],
        eventKeys: ekuboEventKeys.length
          ? ekuboEventKeys
          : ['0x157717768aca88da4ac4279765f09f4d0151823d573537fbbeb950cdbd9a870'],
      }]
      : []),
  ];

  return {
    rpcUrl: String(import.meta.env.VITE_RPC_URL ?? 'https://starknet-mainnet.public.blastapi.io/rpc/v0_8'),
    pragmaBaseUrl: String(import.meta.env.VITE_PRAGMA_BASE_URL ?? ''),
    pragmaPair: String(import.meta.env.VITE_PRAGMA_PAIR ?? 'ETH/USD'),
    pragmaTimeoutMs,
    lookbackBlocks,
    protocols,
  };
}

function publicInputsToBytes(publicInputs: string[]): Uint8Array {
  const result = new Uint8Array(publicInputs.length * 32);
  for (let i = 0; i < publicInputs.length; i++) {
    const hex = publicInputs[i].replace(/^0x/, '').padStart(64, '0');
    for (let j = 0; j < 32; j++) {
      result[i * 32 + j] = parseInt(hex.substring(j * 2, j * 2 + 2), 16);
    }
  }
  return result;
}

function parseCsvEnv(value: unknown): string[] {
  if (!value) return [];
  return String(value).split(',').map((item) => item.trim()).filter(Boolean);
}

function extractVerificationResult(result: unknown): boolean {
  if (typeof result === 'boolean') return result;
  if (result === 1n || result === 1) return true;
  if (result === 0n || result === 0) return false;

  if (result && typeof result === 'object') {
    const r = result as Record<string, unknown>;
    if ('Some' in r) return Boolean(r.Some);
    if (r.variant_id === 0 || r.variant_id === 0n) return Boolean(r.value ?? r[1] ?? true);
    if ('0' in r && r['0'] !== undefined) {
      const inner = r['0'];
      if (typeof inner === 'boolean') return inner;
      return inner === 1n || inner === 1;
    }
  }

  return Boolean(result);
}
