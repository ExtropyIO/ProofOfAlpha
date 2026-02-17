import { Noir } from '@noir-lang/noir_js';
import initNoirC from '@noir-lang/noirc_abi';
import initACVM from '@noir-lang/acvm_js';
// @ts-ignore Vite wasm?url import
import acvm from '@noir-lang/acvm_js/web/acvm_js_bg.wasm?url';
// @ts-ignore Vite wasm?url import
import noirc from '@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url';
import { UltraHonkBackend } from '@aztec/bb.js';
import circuit from '../assets/circuit.json';

export interface RoiProofInputs {
  totalIn: bigint;
  totalOut: bigint;
  thresholdBps: number;
  tradeCount: number;
}

export interface RoiProofResult {
  proof: Uint8Array;
  publicInputs: string[];
  elapsedMs: number;
}

export type ProofProgressCallback = (stage: string) => void;

let wasmReady = false;

async function ensureWasm(): Promise<void> {
  if (wasmReady) return;
  await Promise.all([initACVM(fetch(acvm)), initNoirC(fetch(noirc))]);
  wasmReady = true;
}

export async function generateRoiProof(
  inputs: RoiProofInputs,
  onProgress?: ProofProgressCallback,
): Promise<RoiProofResult> {
  const t0 = performance.now();

  onProgress?.('Initialising WASM…');
  await ensureWasm();

  const circuitInputs: Record<string, string> = {
    total_in: '0x' + inputs.totalIn.toString(16),
    total_out: '0x' + inputs.totalOut.toString(16),
    threshold_bps: '0x' + inputs.thresholdBps.toString(16),
    trade_count: '0x' + inputs.tradeCount.toString(16),
  };

  onProgress?.('Generating witness…');
  const noir = new Noir(circuit as never);
  const { witness } = await noir.execute(circuitInputs);

  onProgress?.('Generating proof…');
  const backend = new UltraHonkBackend((circuit as { bytecode: string }).bytecode);
  const proof = await backend.generateProof(witness);

  const elapsedMs = Math.round(performance.now() - t0);

  const proofBytes = proof.proof instanceof Uint8Array
    ? proof.proof
    : new Uint8Array(proof.proof as ArrayBuffer);

  const publicInputs: string[] = Array.isArray(proof.publicInputs)
    ? (proof.publicInputs as string[])
    : [];

  return { proof: proofBytes, publicInputs, elapsedMs };
}

export async function verifyRoiProof(
  proofBytes: Uint8Array,
  publicInputs: string[],
): Promise<boolean> {
  await ensureWasm();
  const backend = new UltraHonkBackend((circuit as { bytecode: string }).bytecode);
  return backend.verifyProof({ proof: proofBytes, publicInputs });
}
