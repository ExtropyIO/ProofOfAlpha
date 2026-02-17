// CRS fetch with CDN fallback — default crs.aztec.network is frequently down

const CRS_BASE_URLS = [
  'https://crs.aztec-cdn.foundation',
  'https://crs.aztec-labs.com',
  'https://crs.aztec.network',
];

async function fetchWithFallback(
  path: string,
  init?: RequestInit
): Promise<Response> {
  let lastError: unknown;
  for (const base of CRS_BASE_URLS) {
    try {
      const res = await fetch(`${base}${path}`, init);
      if (res.ok) return res;
      lastError = new Error(`HTTP ${res.status}`);
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError;
}

function* makeBackoff(intervals: number[]) {
  for (const s of intervals) {
    yield s;
  }
}

async function retry<T>(
  fn: () => Promise<T>,
  backoff: Generator<number, void, unknown> = makeBackoff([5, 5, 5])
): Promise<T> {
  while (true) {
    try {
      return await fn();
    } catch (err) {
      const s = backoff.next().value;
      if (s === undefined) throw err;
      await new Promise((r) => setTimeout(r, s * 1000));
    }
  }
}

export class NetCrs {
  private data!: Uint8Array;
  private g2Data!: Uint8Array;

  constructor(public readonly numPoints: number) { }

  async init() {
    await this.downloadG1Data();
    await this.downloadG2Data();
  }

  async streamG1Data(): Promise<ReadableStream<Uint8Array>> {
    const response = await this.fetchG1Data();
    return response.body!;
  }

  async streamG2Data(): Promise<ReadableStream<Uint8Array>> {
    const response = await this.fetchG2Data();
    return response.body!;
  }

  async downloadG1Data() {
    const response = await this.fetchG1Data();
    return (this.data = new Uint8Array(await response.arrayBuffer()));
  }

  async downloadG2Data() {
    const response2 = await this.fetchG2Data();
    return (this.g2Data = new Uint8Array(await response2.arrayBuffer()));
  }

  getG1Data(): Uint8Array {
    return this.data;
  }

  getG2Data(): Uint8Array {
    return this.g2Data;
  }

  private async fetchG1Data(): Promise<Response> {
    if (this.numPoints === 0) {
      return new Response(new Uint8Array([]));
    }
    const g1End = this.numPoints * 64 - 1;
    return await retry(
      () =>
        fetchWithFallback('/g1.dat', {
          headers: { Range: `bytes=0-${g1End}` },
          cache: 'force-cache',
        }),
      makeBackoff([5, 5, 5])
    );
  }

  private async fetchG2Data(): Promise<Response> {
    return await retry(
      () =>
        fetchWithFallback('/g2.dat', {
          cache: 'force-cache',
        }),
      makeBackoff([5, 5, 5])
    );
  }
}

export class NetGrumpkinCrs {
  private data!: Uint8Array;

  constructor(public readonly numPoints: number) { }

  async init() {
    await this.downloadG1Data();
  }

  async downloadG1Data() {
    const response = await this.fetchG1Data();
    return (this.data = new Uint8Array(await response.arrayBuffer()));
  }

  async streamG1Data(): Promise<ReadableStream<Uint8Array>> {
    const response = await this.fetchG1Data();
    return response.body!;
  }

  getG1Data(): Uint8Array {
    return this.data;
  }

  private async fetchG1Data(): Promise<Response> {
    if (this.numPoints === 0) {
      return new Response(new Uint8Array([]));
    }
    const g1End = this.numPoints * 64 - 1;
    return fetchWithFallback('/grumpkin_g1.dat', {
      headers: { Range: `bytes=0-${g1End}` },
      cache: 'force-cache',
    });
  }
}
