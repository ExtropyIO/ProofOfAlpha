import { RpcProvider, hash, type BlockIdentifier, type EventFilter } from 'starknet';

type BlockRef = 'latest' | number;

const TRANSFER_SELECTOR = '0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9';

interface TokenMeta {
  symbol: string;
  address: string;
  decimals: number;
  pragmaPair: string | null; // null = stablecoin pegged at $1
}

const WELL_KNOWN_TOKENS: TokenMeta[] = [
  { symbol: 'ETH',  address: '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7', decimals: 18, pragmaPair: 'ETH/USD' },
  { symbol: 'STRK', address: '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d', decimals: 18, pragmaPair: 'STRK/USD' },
  { symbol: 'USDC', address: '0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8', decimals: 6,  pragmaPair: null },
  { symbol: 'USDT', address: '0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8', decimals: 6,  pragmaPair: null },
  { symbol: 'WBTC', address: '0x03fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac', decimals: 8,  pragmaPair: 'BTC/USD' },
];

const TOKEN_BY_SYMBOL = new Map(WELL_KNOWN_TOKENS.map((t) => [t.symbol, t]));

export interface SwapProtocolConfig {
  name: string;
  contractAddress: string;
  eventNames: string[];
  eventKeys?: string[];
  userAddressKeyIndices?: number[];
  userAddressDataIndices?: number[];
  amountInDataIndex?: number;
  amountOutDataIndex?: number;
}

export interface PragmaConfig {
  baseUrl: string;
  queryParams?: Record<string, string>;
  apiKey?: string;
  timeoutMs?: number;
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
  amountInUsd: bigint | null;
  amountOutUsd: bigint | null;
  inTokenSymbol: string | null;
  outTokenSymbol: string | null;
}

export interface FetchSwapsInput {
  userAddress: string;
  fromBlock?: BlockRef;
  toBlock?: BlockRef;
  chunkSize?: number;
  maxEventsToScan?: number;
  maxSenderLookups?: number;
}

export interface FetchRecentSwapsInput {
  userAddress: string;
  lookbackBlocks?: number;
  toBlock?: BlockRef;
  chunkSize?: number;
}

export interface TradeRoiSummary {
  tradeCount: number;
  pricedTradeCount: number;
  winningTradeCount: number;
  winRateBps: number | null;
  totalInUsd: string;
  totalOutUsd: string;
  pnlUsd: string;
  roiBps: number | null;
  proofInputHint: { totalIn: string; totalOut: string; tradeCount: number } | null;
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
    const maxEventsToScan = input.maxEventsToScan ?? 2000;
    const maxSenderLookups = input.maxSenderLookups ?? 50;

    const blockTimestampCache = new Map<number, number | null>();
    const txSenderCache = new Map<string, string | null>();
    const allResults: SwapEventRecord[] = [];
    let totalEventsScanned = 0;
    let totalSenderLookups = 0;

    for (const protocol of this.protocols) {
      const selectors = getProtocolEventSelectors(protocol);
      for (const { eventName, selector } of selectors) {
        let continuationToken: string | undefined;
        const seenTokens = new Set<string>();
        let hitScanLimit = false;

        do {
          const chunk = await this.provider.getEvents({
            address: protocol.contractAddress,
            from_block: asBlockIdentifier(fromBlock),
            to_block: asBlockIdentifier(toBlock),
            keys: selector ? [[selector]] : undefined,
            continuation_token: continuationToken,
            chunk_size: chunkSize,
          } as EventFilter);

          const events = chunk.events ?? [];
          totalEventsScanned += events.length;

          const mappedEvents = events.map((event) => {
            const keys = ((event as { keys?: string[] }).keys ?? []).map(normalizeHex);
            const data = ((event as { data?: string[] }).data ?? []).map(normalizeHex);
            const txHash = String((event as { transaction_hash?: string }).transaction_hash ?? '');
            const directMatch = eventContainsUserAddress(userAddress, keys, data, protocol);
            return { event, keys, data, txHash, directMatch };
          });

          const senderLookupsRemaining = maxSenderLookups - totalSenderLookups;
          if (senderLookupsRemaining > 0) {
            const txHashesNeedingSenderLookup = Array.from(new Set(
              mappedEvents
                .filter((item) => !item.directMatch && Boolean(item.txHash))
                .map((item) => item.txHash),
            )).filter((h) => !txSenderCache.has(normalizeHex(h)));

            const batch = txHashesNeedingSenderLookup.slice(0, senderLookupsRemaining);
            if (batch.length > 0) {
              await this.resolveTransactionSenders(batch, txSenderCache);
              totalSenderLookups += batch.length;
            }
          }

          for (const item of mappedEvents) {
            const senderMatch =
              !item.directMatch && item.txHash
                ? (txSenderCache.get(normalizeHex(item.txHash)) ?? null) === userAddress
                : false;
            if (!item.directMatch && !senderMatch) continue;

            const blockNumber = readBlockNumber(item.event);
            const timestamp = await this.getBlockTimestamp(blockNumber, blockTimestampCache);
            const amountInRaw = readAmountAtIndex(item.data, protocol.amountInDataIndex);
            const amountOutRaw = readAmountAtIndex(item.data, protocol.amountOutDataIndex);

            allResults.push({
              protocol: protocol.name,
              contractAddress: protocol.contractAddress,
              eventName,
              txHash: item.txHash,
              blockNumber,
              timestamp,
              userAddress,
              amountInRaw,
              amountOutRaw,
              keys: item.keys,
              data: item.data,
            });
          }

          continuationToken = (chunk as { continuation_token?: string }).continuation_token;

          if (continuationToken) {
            if (seenTokens.has(continuationToken)) {
              console.warn(`Repeated continuation token for ${protocol.name}/${eventName}; stopping.`);
              continuationToken = undefined;
            } else {
              seenTokens.add(continuationToken);
            }
          }

          if (totalEventsScanned >= maxEventsToScan) {
            hitScanLimit = true;
            break;
          }
        } while (continuationToken);

        if (hitScanLimit) break;
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

  private async resolveTransactionSenders(
    txHashes: string[],
    cache: Map<string, string | null>,
  ): Promise<void> {
    await runWithConcurrency(txHashes, 12, async (txHash) => {
      await this.getTransactionSender(txHash, cache);
    });
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
      amountInUsd: null,
      amountOutUsd: null,
      inTokenSymbol: null,
      outTokenSymbol: null,
    }));
  }

  async fetchRecentSwapsWithPragma(input: FetchRecentSwapsInput): Promise<SwapWithPrice[]> {
    const toBlockRef = input.toBlock ?? 'latest';
    const toBlockNumber = await this.resolveBlockNumber(toBlockRef);
    const lookback = Math.max(1, input.lookbackBlocks ?? 1200);
    const fromBlock = Math.max(0, toBlockNumber - lookback);

    const swaps = await this.fetchUserSwapsViaTransfers({
      userAddress: input.userAddress,
      fromBlock,
      toBlock: toBlockNumber,
      windowSize: 1000,
      maxTimeMs: 25_000,
    });

    // Collect unique (pragmaPair, timestamp) combos we need prices for
    const priceFetchKeys = new Set<string>();
    for (const swap of swaps) {
      if (swap.timestamp === null) continue;
      for (const entry of swap.data) {
        const parsed = parseTransferEntry(entry);
        if (!parsed) continue;
        const meta = TOKEN_BY_SYMBOL.get(parsed.symbol);
        if (meta?.pragmaPair) priceFetchKeys.add(`${meta.pragmaPair}:${swap.timestamp}`);
      }
    }

    // Fetch all needed prices in parallel, keyed by "PAIR:timestamp"
    const priceCache = new Map<string, { price: bigint; decimals: number } | null>();
    const firstPragma = new Map<number, PragmaPriceUpdate | null>();
    await Promise.all(
      Array.from(priceFetchKeys).map(async (key) => {
        const [pair, tsStr] = key.split(':');
        const ts = Number(tsStr);
        try {
          const update = await this.fetchPragmaUpdate(ts, pair);
          priceCache.set(key, extractPriceFromPayload(update.payload));
          if (!firstPragma.has(ts)) firstPragma.set(ts, update);
        } catch (error) {
          console.error(`Pragma fetch failed for ${key}`, error);
          priceCache.set(key, null);
        }
      }),
    );

    return swaps.map((swap) => {
      const transfers = swap.data.map(parseTransferEntry).filter(Boolean) as ParsedTransfer[];
      const outgoing = transfers.filter((t) => t.direction === 'from');
      const incoming = transfers.filter((t) => t.direction === 'to');

      const amountInUsd = swap.timestamp !== null
        ? sumTransfersToMicroUsd(outgoing, swap.timestamp, priceCache)
        : null;
      const amountOutUsd = swap.timestamp !== null
        ? sumTransfersToMicroUsd(incoming, swap.timestamp, priceCache)
        : null;

      return {
        ...swap,
        pragma: swap.timestamp === null ? null : (firstPragma.get(swap.timestamp) ?? null),
        amountInUsd,
        amountOutUsd,
        inTokenSymbol: outgoing[0]?.symbol ?? null,
        outTokenSymbol: incoming[0]?.symbol ?? null,
      };
    });
  }

  // Scans ERC-20 Transfer events on well-known tokens in reverse block order.
  // Groups transfers by tx hash — if a tx has both outgoing + incoming for the
  // user, it's treated as a swap.
  async fetchUserSwapsViaTransfers(input: {
    userAddress: string;
    fromBlock: number;
    toBlock: number;
    windowSize?: number;
    maxTimeMs?: number;
  }): Promise<SwapEventRecord[]> {
    const userAddress = normalizeHex(input.userAddress);
    const windowSize = input.windowSize ?? 1000;
    const maxTimeMs = input.maxTimeMs ?? 25_000;
    const startTime = Date.now();
    const blockTimestampCache = new Map<number, number | null>();

    interface UserTransfer {
      tokenSymbol: string;
      tokenAddress: string;
      txHash: string;
      blockNumber: number | null;
      direction: 'from' | 'to';
      amountRaw: string;
    }

    const allTransfers: UserTransfer[] = [];
    let currentTo = input.toBlock;

    while (currentTo >= input.fromBlock) {
      if (Date.now() - startTime > maxTimeMs) {
        console.warn(`Transfer scan timed out after ${maxTimeMs}ms at block ${currentTo}`);
        break;
      }

      const currentFrom = Math.max(currentTo - windowSize + 1, input.fromBlock);

      for (const token of WELL_KNOWN_TOKENS) {
        if (Date.now() - startTime > maxTimeMs) break;

        try {
          let continuationToken: string | undefined;
          do {
            const chunk = await this.provider.getEvents({
              address: token.address,
              from_block: asBlockIdentifier(currentFrom),
              to_block: asBlockIdentifier(currentTo),
              keys: [[TRANSFER_SELECTOR]],
              continuation_token: continuationToken,
              chunk_size: 1000,
            } as EventFilter);

            for (const event of chunk.events ?? []) {
              const data = ((event as { data?: string[] }).data ?? []).map(normalizeHex);
              if (data.length < 3) continue;

              const fromAddr = data[0];
              const toAddr = data[1];
              const isFromUser = fromAddr === userAddress;
              const isToUser = toAddr === userAddress;
              if (!isFromUser && !isToUser) continue;

              const txHash = String((event as { transaction_hash?: string }).transaction_hash ?? '');
              const blockNumber = readBlockNumber(event);
              const amountLow = BigInt(data[2] || '0x0');
              const amountHigh = data.length > 3 ? BigInt(data[3] || '0x0') : 0n;
              const amount = amountLow + (amountHigh << 128n);

              allTransfers.push({
                tokenSymbol: token.symbol,
                tokenAddress: normalizeHex(token.address),
                txHash,
                blockNumber,
                direction: isFromUser ? 'from' : 'to',
                amountRaw: '0x' + amount.toString(16),
              });
            }

            continuationToken = (chunk as { continuation_token?: string }).continuation_token;
          } while (continuationToken && Date.now() - startTime < maxTimeMs);
        } catch (error) {
          console.warn(`Transfer scan failed for ${token.symbol} in blocks ${currentFrom}-${currentTo}:`, error);
        }
      }

      currentTo = currentFrom - 1;
      if (allTransfers.length > 0) break;
    }

    const byTxHash = new Map<string, UserTransfer[]>();
    for (const transfer of allTransfers) {
      if (!transfer.txHash) continue;
      const key = normalizeHex(transfer.txHash);
      const arr = byTxHash.get(key) ?? [];
      arr.push(transfer);
      byTxHash.set(key, arr);
    }

    const results: SwapEventRecord[] = [];
    for (const [txHash, transfers] of byTxHash) {
      const outgoing = transfers.filter((t) => t.direction === 'from');
      const incoming = transfers.filter((t) => t.direction === 'to');
      if (outgoing.length === 0 && incoming.length === 0) continue;

      const primary = outgoing[0] ?? incoming[0];
      const blockNumber = primary.blockNumber;
      const timestamp = await this.getBlockTimestamp(blockNumber, blockTimestampCache);
      const protocolName = this.identifyProtocolForTx(transfers);
      const outSummary = outgoing.map((t) => t.tokenSymbol).join('+') || '?';
      const inSummary = incoming.map((t) => t.tokenSymbol).join('+') || '?';

      results.push({
        protocol: protocolName,
        contractAddress: '',
        eventName: `Swap (${outSummary} -> ${inSummary})`,
        txHash,
        blockNumber,
        timestamp,
        userAddress,
        amountInRaw: outgoing[0]?.amountRaw,
        amountOutRaw: incoming[0]?.amountRaw,
        keys: [],
        data: transfers.map((t) => `${t.direction}:${t.tokenSymbol}:${t.amountRaw}`),
      });
    }

    // Fallback: if no paired swaps found, show individual transfers
    if (results.length === 0 && allTransfers.length > 0) {
      for (const transfer of allTransfers) {
        const blockNumber = transfer.blockNumber;
        const timestamp = await this.getBlockTimestamp(blockNumber, blockTimestampCache);
        results.push({
          protocol: 'Transfer',
          contractAddress: transfer.tokenAddress,
          eventName: `${transfer.direction === 'from' ? 'Send' : 'Receive'} ${transfer.tokenSymbol}`,
          txHash: transfer.txHash,
          blockNumber,
          timestamp,
          userAddress,
          amountInRaw: transfer.direction === 'from' ? transfer.amountRaw : undefined,
          amountOutRaw: transfer.direction === 'to' ? transfer.amountRaw : undefined,
          keys: [],
          data: [`${transfer.direction}:${transfer.tokenSymbol}:${transfer.amountRaw}`],
        });
      }
    }

    results.sort((a, b) => {
      const at = a.timestamp ?? Number.MAX_SAFE_INTEGER;
      const bt = b.timestamp ?? Number.MAX_SAFE_INTEGER;
      return bt - at;
    });

    return results;
  }

  private identifyProtocolForTx(transfers: Array<{ tokenAddress: string }>): string {
    for (const protocol of this.protocols) {
      const protoAddr = normalizeHex(protocol.contractAddress);
      for (const t of transfers) {
        if (normalizeHex(t.tokenAddress) === protoAddr) {
          return protocol.name;
        }
      }
    }
    return 'DEX Swap';
  }

  private async resolveBlockNumber(block: BlockRef): Promise<number> {
    if (typeof block === 'number') return Math.max(0, Math.floor(block));
    if (block !== 'latest') return 0;

    const latest = await this.provider.getBlock('latest');
    const latestBlockRaw = (latest as { block_number?: number | string }).block_number;
    const latestBlockNumber = Number(latestBlockRaw);
    if (!Number.isFinite(latestBlockNumber)) {
      throw new Error('Failed to resolve latest Starknet block number.');
    }
    return Math.max(0, Math.floor(latestBlockNumber));
  }

  private async fetchPragmaUpdate(timestamp: number, pairOverride?: string): Promise<PragmaPriceUpdate> {
    const baseUrl = this.pragma.baseUrl.replace(/\/+$/, '');
    if (!baseUrl) throw new Error('Pragma base URL is not configured.');

    // pair = "ETH/USD" → base="ETH", quote="USD"
    const pair = pairOverride ?? this.pragma.queryParams?.pair ?? 'ETH/USD';
    const [base, quote] = pair.split('/');
    const url = new URL(`${baseUrl}/onchain/${base}/${quote}`);
    url.searchParams.set('network', 'starknet-mainnet');
    url.searchParams.set('timestamp', String(timestamp));

    const headers: HeadersInit = {};
    if (this.pragma.apiKey) {
      headers['X-API-KEY'] = this.pragma.apiKey;
    }

    const timeoutMs = this.pragma.timeoutMs ?? 10_000;
    const response = await fetchWithTimeout(url.toString(), { headers }, timeoutMs);
    if (!response.ok) {
      throw new Error(`Pragma ${pair} request failed (${response.status} ${response.statusText})`);
    }

    const payload = (await response.json()) as unknown;
    return { timestamp, signature: extractSignature(payload), payload };
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
    if (swap.amountInUsd === null || swap.amountOutUsd === null) continue;

    totalIn += swap.amountInUsd;
    totalOut += swap.amountOutUsd;
    pricedTradeCount += 1;
    if (swap.amountOutUsd > swap.amountInUsd) winningTradeCount += 1;
  }

  const pnl = totalOut - totalIn;
  const roiBps = totalIn > 0n ? Number((pnl * 10_000n) / totalIn) : null;
  const winRateBps = pricedTradeCount > 0 ? Math.round((winningTradeCount * 10_000) / pricedTradeCount) : null;

  return {
    tradeCount: swaps.length,
    pricedTradeCount,
    winningTradeCount,
    winRateBps,
    totalInUsd: totalIn.toString(),
    totalOutUsd: totalOut.toString(),
    pnlUsd: pnl.toString(),
    roiBps,
    proofInputHint: buildProofInputHint(totalIn, totalOut, pricedTradeCount),
  };
}

function asBlockIdentifier(block: BlockRef): BlockIdentifier {
  if (block === 'latest') return { block_tag: 'latest' } as unknown as BlockIdentifier;
  return { block_number: block } as unknown as BlockIdentifier;
}

function normalizeHex(value: string): string {
  const v = value.toLowerCase();
  const withPrefix = v.startsWith('0x') ? v : `0x${v}`;
  const stripped = withPrefix.replace(/^0x0+/, '0x');
  return stripped === '0x' ? '0x0' : stripped;
}

function getProtocolEventSelectors(protocol: SwapProtocolConfig): Array<{ eventName: string; selector?: string }> {
  const fromNames = protocol.eventNames.map((eventName) => ({
    eventName,
    selector: hash.getSelectorFromName(eventName),
  }));

  const fromExplicitKeys = (protocol.eventKeys ?? []).map((eventKey, idx) => ({
    eventName: `${protocol.name}-event-${idx + 1}`,
    selector: normalizeHex(eventKey),
  }));

  const merged = [...fromNames, ...fromExplicitKeys];
  if (!merged.length) return [{ eventName: `${protocol.name}-all-events` }];

  const deduped = new Map<string, { eventName: string; selector?: string }>();
  for (const item of merged) {
    const key = item.selector ?? item.eventName;
    if (!deduped.has(key)) deduped.set(key, item);
  }
  return Array.from(deduped.values());
}

function readAmountAtIndex(data: string[], index?: number): string | undefined {
  if (index === undefined || index < 0 || index >= data.length) return undefined;
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

  return keys.includes(userAddress) || data.includes(userAddress);
}

function extractSignature(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;

  if (typeof p.signature === 'string') return p.signature;

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

  if (Array.isArray(p.signatures) && typeof p.signatures[0] === 'string') {
    return p.signatures[0];
  }

  return null;
}

function parseRawAmount(value: string | undefined): bigint | null {
  if (!value) return null;
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) return null;

  try {
    if (trimmed.startsWith('0x')) return BigInt(trimmed);
    if (/^-?\d+$/.test(trimmed)) return BigInt(trimmed);
  } catch {
    return null;
  }
  return null;
}

interface ParsedTransfer {
  direction: 'from' | 'to';
  symbol: string;
  amountRaw: string;
}

function parseTransferEntry(entry: string): ParsedTransfer | null {
  const parts = entry.split(':');
  if (parts.length < 3) return null;
  const direction = parts[0] as 'from' | 'to';
  if (direction !== 'from' && direction !== 'to') return null;
  return { direction, symbol: parts[1], amountRaw: parts.slice(2).join(':') };
}

function extractPriceFromPayload(payload: unknown): { price: bigint; decimals: number } | null {
  const obj = deepFindPriceFields(payload);
  if (!obj) return null;
  try {
    return { price: BigInt(String(obj.price)), decimals: Number(obj.decimals) };
  } catch {
    return null;
  }
}

function deepFindPriceFields(payload: unknown): { price: unknown; decimals: unknown } | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;
  if (p.price !== undefined && p.decimals !== undefined) return { price: p.price, decimals: p.decimals };
  for (const key of ['data', 'result', '0']) {
    const nested = p[key];
    if (nested && typeof nested === 'object') {
      const found = deepFindPriceFields(nested);
      if (found) return found;
    }
  }
  return null;
}

function convertToMicroUsd(
  rawAmount: bigint,
  tokenDecimals: number,
  price: bigint,
  priceDecimals: number,
): bigint {
  // result = rawAmount * price / 10^(tokenDecimals + priceDecimals - 6)
  const scalePow = tokenDecimals + priceDecimals - 6;
  if (scalePow <= 0) return rawAmount * price * (10n ** BigInt(-scalePow));
  return (rawAmount * price) / (10n ** BigInt(scalePow));
}

function sumTransfersToMicroUsd(
  transfers: ParsedTransfer[],
  timestamp: number,
  priceCache: Map<string, { price: bigint; decimals: number } | null>,
): bigint | null {
  let sum = 0n;
  let anyConverted = false;

  for (const t of transfers) {
    const rawAmount = parseRawAmount(t.amountRaw);
    if (rawAmount === null || rawAmount === 0n) continue;

    const meta = TOKEN_BY_SYMBOL.get(t.symbol);
    if (!meta) continue;

    if (meta.pragmaPair === null) {
      // Stablecoin — rawAmount is already in the token's smallest unit (6 decimals = micro-USD)
      sum += rawAmount;
      anyConverted = true;
      continue;
    }

    const priceData = priceCache.get(`${meta.pragmaPair}:${timestamp}`);
    if (!priceData) continue;

    sum += convertToMicroUsd(rawAmount, meta.decimals, priceData.price, priceData.decimals);
    anyConverted = true;
  }

  return anyConverted ? sum : null;
}

function buildProofInputHint(
  totalIn: bigint,
  totalOut: bigint,
  pricedTradeCount: number,
): { totalIn: string; totalOut: string; tradeCount: number } | null {
  if (pricedTradeCount === 0 || totalIn <= 0n) return null;
  return {
    totalIn: '0x' + totalIn.toString(16),
    totalOut: '0x' + totalOut.toString(16),
    tradeCount: pricedTradeCount,
  };
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

async function runWithConcurrency<T>(
  items: T[],
  concurrency: number,
  worker: (item: T) => Promise<void>,
): Promise<void> {
  if (!items.length) return;
  const width = Math.max(1, Math.floor(concurrency));
  let cursor = 0;

  const runners = Array.from({ length: Math.min(width, items.length) }, async () => {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      await worker(items[index]);
    }
  });

  await Promise.all(runners);
}
