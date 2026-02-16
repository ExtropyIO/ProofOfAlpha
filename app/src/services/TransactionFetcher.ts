import { RpcProvider, hash, type BlockIdentifier, type EventFilter } from 'starknet';

type BlockRef = 'latest' | number;

export interface SwapProtocolConfig {
  name: string;
  contractAddress: string;
  eventNames: string[];
  /**
   * Optional explicit event key positions where user address is expected.
   * If omitted, the matcher falls back to "address appears in keys/data".
   */
  userAddressKeyIndices?: number[];
  userAddressDataIndices?: number[];
  /** Optional data positions for amount extraction. */
  amountInDataIndex?: number;
  amountOutDataIndex?: number;
}

export interface PragmaConfig {
  baseUrl: string;
  /**
   * Optional query params required by your Pragma endpoint setup
   * (examples: pair, network, source).
   */
  queryParams?: Record<string, string>;
  apiKey?: string;
}

export interface SwapEventRecord {
  protocol: string;
  contractAddress: string;
  eventName: string;
  txHash: string;
  blockNumber: number | null;
  timestamp: number | null;
  userAddress: string;
  amountInRaw?: string;
  amountOutRaw?: string;
  keys: string[];
  data: string[];
}

export interface PragmaPriceUpdate {
  timestamp: number;
  signature: string | null;
  payload: unknown;
}

export interface SwapWithPrice extends SwapEventRecord {
  pragma: PragmaPriceUpdate | null;
}

export interface FetchSwapsInput {
  userAddress: string;
  fromBlock?: BlockRef;
  toBlock?: BlockRef;
  chunkSize?: number;
}

export interface FetchRecentSwapsInput {
  userAddress: string;
  /**
   * Number of blocks to scan backwards from the resolved toBlock.
   * Defaults to 1200.
   */
  lookbackBlocks?: number;
  toBlock?: BlockRef;
  chunkSize?: number;
}

export interface TradeRoiSummary {
  tradeCount: number;
  pricedTradeCount: number;
  winningTradeCount: number;
  winRateBps: number | null;
  totalInRaw: string;
  totalOutRaw: string;
  pnlRaw: string;
  roiBps: number | null;
  /**
   * Suggested integers to feed the current sample circuit inputs.
   * This is an adapter for frontend UX while the dedicated ROI circuit is pending.
   */
  proofInputHint: { x: number; y: number } | null;
}

export class TransactionFetcher {
  private provider: RpcProvider;
  private protocols: SwapProtocolConfig[];
  private pragma: PragmaConfig;

  constructor(provider: RpcProvider, protocols: SwapProtocolConfig[], pragma: PragmaConfig) {
    this.provider = provider;
    this.protocols = protocols;
    this.pragma = pragma;
  }

  async fetchSwapEvents(input: FetchSwapsInput): Promise<SwapEventRecord[]> {
    const userAddress = normalizeHex(input.userAddress);
    const fromBlock = input.fromBlock ?? 0;
    const toBlock = input.toBlock ?? 'latest';
    const chunkSize = input.chunkSize ?? 200;

    const blockTimestampCache = new Map<number, number | null>();
    const txSenderCache = new Map<string, string | null>();
    const allResults: SwapEventRecord[] = [];

    for (const protocol of this.protocols) {
      for (const eventName of protocol.eventNames) {
        const selector = hash.getSelectorFromName(eventName);
        let continuationToken: string | undefined;

        do {
          const chunk = await this.provider.getEvents({
            address: protocol.contractAddress,
            from_block: asBlockIdentifier(fromBlock),
            to_block: asBlockIdentifier(toBlock),
            keys: [[selector]],
            continuation_token: continuationToken,
            chunk_size: chunkSize,
          } as EventFilter);

          for (const event of chunk.events ?? []) {
            const keys = ((event as { keys?: string[] }).keys ?? []).map(normalizeHex);
            const data = ((event as { data?: string[] }).data ?? []).map(normalizeHex);
            const txHash = String((event as { transaction_hash?: string }).transaction_hash ?? '');

            let isUserMatch = eventContainsUserAddress(userAddress, keys, data, protocol);
            if (!isUserMatch && txHash) {
              const txSender = await this.getTransactionSender(txHash, txSenderCache);
              isUserMatch = txSender === userAddress;
            }

            if (!isUserMatch) {
              continue;
            }

            const blockNumber = readBlockNumber(event);
            const timestamp = await this.getBlockTimestamp(blockNumber, blockTimestampCache);

            const amountInRaw = readAmountAtIndex(data, protocol.amountInDataIndex);
            const amountOutRaw = readAmountAtIndex(data, protocol.amountOutDataIndex);

            allResults.push({
              protocol: protocol.name,
              contractAddress: protocol.contractAddress,
              eventName,
              txHash,
              blockNumber,
              timestamp,
              userAddress,
              amountInRaw,
              amountOutRaw,
              keys,
              data,
            });
          }

          continuationToken = (chunk as { continuation_token?: string }).continuation_token;
        } while (continuationToken);
      }
    }

    allResults.sort((a, b) => {
      const at = a.timestamp ?? Number.MAX_SAFE_INTEGER;
      const bt = b.timestamp ?? Number.MAX_SAFE_INTEGER;
      return at - bt;
    });

    return allResults;
  }

  private async getTransactionSender(
    txHash: string,
    cache: Map<string, string | null>,
  ): Promise<string | null> {
    const normalizedHash = normalizeHex(txHash);
    if (cache.has(normalizedHash)) {
      return cache.get(normalizedHash) ?? null;
    }

    try {
      const tx = await this.provider.getTransactionByHash(normalizedHash);
      const senderRaw = (tx as { sender_address?: string }).sender_address;
      const sender = senderRaw ? normalizeHex(senderRaw) : null;
      cache.set(normalizedHash, sender);
      return sender;
    } catch (error) {
      console.warn(`Failed to resolve sender for tx ${normalizedHash}`, error);
      cache.set(normalizedHash, null);
      return null;
    }
  }

  async fetchSwapsWithPragma(input: FetchSwapsInput): Promise<SwapWithPrice[]> {
    const swaps = await this.fetchSwapEvents(input);
    const uniqueTimestamps = Array.from(new Set(swaps.map((s) => s.timestamp).filter((t): t is number => t !== null)));

    const pragmaByTimestamp = new Map<number, PragmaPriceUpdate | null>();
    await Promise.all(
      uniqueTimestamps.map(async (timestamp) => {
        try {
          const update = await this.fetchPragmaUpdate(timestamp);
          pragmaByTimestamp.set(timestamp, update);
        } catch (error) {
          console.error(`Pragma fetch failed for timestamp=${timestamp}`, error);
          pragmaByTimestamp.set(timestamp, null);
        }
      }),
    );

    return swaps.map((swap) => ({
      ...swap,
      pragma: swap.timestamp === null ? null : (pragmaByTimestamp.get(swap.timestamp) ?? null),
    }));
  }

  async fetchRecentSwapsWithPragma(input: FetchRecentSwapsInput): Promise<SwapWithPrice[]> {
    const toBlockRef = input.toBlock ?? 'latest';
    const toBlockNumber = await this.resolveBlockNumber(toBlockRef);
    const lookback = Math.max(1, input.lookbackBlocks ?? 1200);
    const fromBlock = Math.max(0, toBlockNumber - lookback);

    return this.fetchSwapsWithPragma({
      userAddress: input.userAddress,
      fromBlock,
      toBlock: toBlockNumber,
      chunkSize: input.chunkSize,
    });
  }

  private async resolveBlockNumber(block: BlockRef): Promise<number> {
    if (typeof block === 'number') {
      return Math.max(0, Math.floor(block));
    }

    if (block !== 'latest') {
      return 0;
    }

    const latest = await this.provider.getBlock('latest');
    const latestBlockRaw = (latest as { block_number?: number | string }).block_number;
    const latestBlockNumber = Number(latestBlockRaw);
    if (!Number.isFinite(latestBlockNumber)) {
      throw new Error('Failed to resolve latest Starknet block number.');
    }
    return Math.max(0, Math.floor(latestBlockNumber));
  }

  private async fetchPragmaUpdate(timestamp: number): Promise<PragmaPriceUpdate> {
    const baseUrl = this.pragma.baseUrl.replace(/\/+$/, '');
    const url = new URL(`${baseUrl}/v1/updates/price/${timestamp}`);
    for (const [key, value] of Object.entries(this.pragma.queryParams ?? {})) {
      url.searchParams.set(key, value);
    }

    const headers: HeadersInit = {};
    if (this.pragma.apiKey) {
      headers['Authorization'] = `Bearer ${this.pragma.apiKey}`;
    }

    const response = await fetch(url.toString(), { headers });
    if (!response.ok) {
      throw new Error(`Pragma request failed (${response.status} ${response.statusText})`);
    }

    const payload = (await response.json()) as unknown;
    return {
      timestamp,
      signature: extractSignature(payload),
      payload,
    };
  }

  private async getBlockTimestamp(
    blockNumber: number | null,
    cache: Map<number, number | null>,
  ): Promise<number | null> {
    if (blockNumber === null) return null;
    if (cache.has(blockNumber)) return cache.get(blockNumber) ?? null;

    try {
      const block = await this.provider.getBlock(blockNumber);
      const timestamp = Number((block as { timestamp?: number | string }).timestamp ?? NaN);
      const normalized = Number.isFinite(timestamp) ? timestamp : null;
      cache.set(blockNumber, normalized);
      return normalized;
    } catch (error) {
      console.error(`Failed to load block ${blockNumber} for timestamp`, error);
      cache.set(blockNumber, null);
      return null;
    }
  }
}

export function computeTradeRoiSummary(swaps: SwapWithPrice[]): TradeRoiSummary {
  let totalIn = 0n;
  let totalOut = 0n;
  let winningTradeCount = 0;
  let pricedTradeCount = 0;

  for (const swap of swaps) {
    const inAmount = parseRawAmount(swap.amountInRaw);
    const outAmount = parseRawAmount(swap.amountOutRaw);
    if (inAmount === null || outAmount === null) {
      continue;
    }

    totalIn += inAmount;
    totalOut += outAmount;
    pricedTradeCount += 1;
    if (outAmount > inAmount) {
      winningTradeCount += 1;
    }
  }

  const pnl = totalOut - totalIn;
  const roiBps = totalIn > 0n ? Number((pnl * 10_000n) / totalIn) : null;
  const winRateBps = pricedTradeCount > 0 ? Math.round((winningTradeCount * 10_000) / pricedTradeCount) : null;

  return {
    tradeCount: swaps.length,
    pricedTradeCount,
    winningTradeCount,
    winRateBps,
    totalInRaw: totalIn.toString(),
    totalOutRaw: totalOut.toString(),
    pnlRaw: pnl.toString(),
    roiBps,
    proofInputHint: buildProofInputHint(roiBps, pricedTradeCount),
  };
}

function asBlockIdentifier(block: BlockRef): BlockIdentifier {
  if (block === 'latest') {
    return { block_tag: 'latest' } as unknown as BlockIdentifier;
  }
  return { block_number: block } as unknown as BlockIdentifier;
}

function normalizeHex(value: string): string {
  const v = value.toLowerCase();
  return v.startsWith('0x') ? v : `0x${v}`;
}

function readAmountAtIndex(data: string[], index?: number): string | undefined {
  if (index === undefined) return undefined;
  if (index < 0 || index >= data.length) return undefined;
  return data[index];
}

function readBlockNumber(event: unknown): number | null {
  const raw = (event as { block_number?: number | string }).block_number;
  if (raw === undefined || raw === null) return null;
  const num = Number(raw);
  return Number.isFinite(num) ? num : null;
}

function eventContainsUserAddress(
  userAddress: string,
  keys: string[],
  data: string[],
  protocol: SwapProtocolConfig,
): boolean {
  const explicitKeyHits =
    protocol.userAddressKeyIndices?.some((i) => i >= 0 && i < keys.length && normalizeHex(keys[i]) === userAddress) ?? false;
  const explicitDataHits =
    protocol.userAddressDataIndices?.some((i) => i >= 0 && i < data.length && normalizeHex(data[i]) === userAddress) ?? false;

  if (protocol.userAddressKeyIndices || protocol.userAddressDataIndices) {
    return explicitKeyHits || explicitDataHits;
  }

  // Safe fallback while protocol-specific decoders are not finalized.
  return keys.includes(userAddress) || data.includes(userAddress);
}

function extractSignature(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;

  const direct = typeof p.signature === 'string' ? p.signature : null;
  if (direct) return direct;

  const dataSig =
    p.data && typeof p.data === 'object' && typeof (p.data as Record<string, unknown>).signature === 'string'
      ? ((p.data as Record<string, unknown>).signature as string)
      : null;
  if (dataSig) return dataSig;

  const resultSig =
    p.result && typeof p.result === 'object' && typeof (p.result as Record<string, unknown>).signature === 'string'
      ? ((p.result as Record<string, unknown>).signature as string)
      : null;
  if (resultSig) return resultSig;

  const signatures = p.signatures;
  if (Array.isArray(signatures) && typeof signatures[0] === 'string') {
    return signatures[0];
  }

  return null;
}

function parseRawAmount(value: string | undefined): bigint | null {
  if (!value) return null;
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) return null;

  try {
    if (trimmed.startsWith('0x')) {
      return BigInt(trimmed);
    }

    if (/^-?\d+$/.test(trimmed)) {
      return BigInt(trimmed);
    }
  } catch {
    return null;
  }

  return null;
}

function buildProofInputHint(roiBps: number | null, pricedTradeCount: number): { x: number; y: number } | null {
  if (roiBps === null) return null;

  const x = clampToCircuitInput(roiBps);
  const y = clampToCircuitInput(pricedTradeCount);
  return { x, y };
}

function clampToCircuitInput(value: number): number {
  if (!Number.isFinite(value)) return 0;
  const rounded = Math.round(value);
  const max = Number.MAX_SAFE_INTEGER;
  if (rounded > max) return max;
  if (rounded < -max) return -max;
  return rounded;
}
