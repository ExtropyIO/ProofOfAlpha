# Proof of Alpha

Prove your DeFi track record on Starknet: connect a wallet, load recent swaps from Jediswap and Ekubo, see an ROI summary, and generate a zero-knowledge proof that your ROI exceeds a chosen threshold—then verify it on-chain without revealing exact amounts.

---

## Architecture

### High-level flow

1. **Frontend (React + Vite)** — Single-page app that:
   - Connects to Starknet via wallet (MetaMask Starknet Snap or get-starknet: ArgentX, Braavos).
   - Fetches swap events for the connected (or manually entered) address from configured protocols.
   - Prices trades in USD using Coingecko-style data and displays an ROI summary.
   - Generates a ZK proof in the browser (Noir + Barretenberg UltraHonk) that “ROI ≥ threshold” without revealing totals.
   - Calls the deployed Garaga verifier contract to verify the proof on Starknet.

2. **Data bridge** — `app/src/services/TransactionFetcher.ts`:
   - Talks to Starknet RPC to get swap events from Jediswap and Ekubo (contract addresses and event keys come from env).
   - Filters by user address, resolves block timestamps, and attaches USD pricing for in/out tokens (ETH, STRK, USDC, USDT, WBTC).
   - Exposes `fetchRecentSwapsWithPrices()` by date range and `computeTradeRoiSummary()` for the UI and proof inputs.

3. **ZK proof** — `app/src/services/ProofGenerator.ts` + Noir circuit:
   - **Circuit** (`circuit/src/main.nr`): Public inputs `threshold_bps`, `trade_count`; private inputs `total_in`, `total_out`. Asserts  
     `total_out * 10000 >= (10000 + threshold_bps) * total_in` (i.e. ROI ≥ threshold) with a 126-bit range check.
   - **ProofGenerator**: Loads compiled `circuit.json`, runs Noir witness + Barretenberg UltraHonk in the browser, returns proof bytes and public inputs. Can verify locally and prepare Garaga calldata for on-chain verification.

4. **Verifier (Starknet)** — Garaga-generated Cairo contract (`contracts/`):
   - Verifies UltraHonk proofs. Deployed to devnet or testnet; frontend calls `verify_ultra_keccak_zk_honk_proof` with calldata from `garaga.getZKHonkCallData(proof, publicInputsBytes, vkBytes)`.

### Frontend app structure

```
app/
├── src/
│   ├── App.tsx              # Main UI: wallet, date range, tx table, ROI summary, proof flow, on-chain verify
│   ├── services/
│   │   ├── TransactionFetcher.ts  # RPC swap fetch, pricing, ROI summary, protocol config
│   │   └── ProofGenerator.ts      # Noir + bb.js proof generation and local verification
│   ├── types/index.ts       # ProofState enum etc.
│   ├── assets/              # circuit.json, vk.bin, verifier.json (copied from circuit/ and contracts/)
│   ├── crs-net-fallback.ts  # CRS URL fallback for bb.js (proof generation)
│   ├── main.tsx, index.css, App.css
│   └── vite-env.d.ts
├── vite.config.ts           # React, node polyfills, CRS rewrite, worker config for bb.js
├── package.json             # React 19, Vite 6, starknet.js, get-starknet, Noir/bb.js/garaga
└── .env                     # VITE_* variables (see below)
```

---

## Frontend setup

### Prerequisites

- **Node.js** ≥ 20  
- **Bun** (recommended for install/scripts). Install: `curl -fsSL https://bun.sh/install | bash`

### Install and run (app only)

```bash
cd app
bun install
bun run dev
```

- Build: `bun run build`  
- Preview production build: `bun run preview`

### Environment variables

Create `app/.env` (or pass env when running). All are optional except where noted.

| Variable                 | Description                                                                  | Example / default                                                                 |
| ------------------------ | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `VITE_RPC_URL`           | Starknet RPC URL                                                             | `https://starknet-mainnet.public.blastapi.io/rpc/v0_8` or your Alchemy/Infura URL |
| `VITE_JEDISWAP_CONTRACT` | Jediswap router/pool for Swap events                                         | Mainnet: `0x0359550b990167afd6635fa574f3bdadd83cb51850e1d00061fe693158c23f80`     |
| `VITE_EKUBO_CONTRACT`    | Ekubo core contract for Swap events                                          | Mainnet: `0x00000005dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b`     |
| `VITE_EKUBO_EVENT_KEYS`  | Comma-separated Ekubo event keys (pool IDs) to filter                        | e.g. `0x157717768aca88da4ac4279765f09f4d0151823d573537fbbeb950cdbd9a870`          |
| `VITE_VERIFIER_ADDRESS`  | Deployed Garaga verifier contract address (required for **Verify on-chain**) | Set after `make deploy-verifier` on devnet                                        |
| `VITE_LOOKBACK_BLOCKS`   | Max blocks to scan when resolving timestamps (TransactionFetcher)            | e.g. `32000`                                                                      |

Without `VITE_VERIFIER_ADDRESS`, the app still runs: you can connect a wallet, fetch swaps, see ROI, and generate proofs; only the “Verify on-chain” button will fail until the verifier is deployed and this env is set.

---

## Test wallet and manual address

- **Connected wallet**  
  Use “Connect Wallet” to use MetaMask Starknet Snap or get-starknet (ArgentX, Braavos). The app uses the first returned account for fetching swaps and proving.

- **Manual address (no wallet)**  
  If you don’t connect a wallet, you can paste a Starknet address in “Manual Starknet address (fallback)” and click **Use Address**. The app will use that address for the data bridge and proof (same flow as with a connected wallet). Useful for testing with a known mainnet address that has history.

- **Devnet testing**  
  When using local devnet (`make devnet`), run `make accounts-file` to generate `contracts/accounts.json`. That file contains a predeployed account (e.g. address and private key) you can use with sncast or with a devnet-compatible wallet. Point `VITE_RPC_URL` to `http://127.0.0.1:5050/rpc` and set `VITE_VERIFIER_ADDRESS` after deploying the verifier (see below).

---

## Main app aspects

1. **Wallet connection**  
   MetaMask Starknet Snap is preferred; fallback is get-starknet (ArgentX, Braavos). Manual address entry allows using the app without any wallet for a given Starknet address.

2. **Data bridge (Recent Transactions)**  
   Fetches swap events from Jediswap and Ekubo for the chosen address and date range, resolves timestamps, and prices in/out in USD. Table shows protocol, event, tx, block, timestamp, amounts, cost (USD), and value (USD).

3. **ROI summary**  
   Aggregates trades into: trade count, priced trade count, ROI %, total spent, portfolio value, PnL. Drives the inputs for the ZK proof (total in/out, trade count).

4. **Prove ROI threshold**  
   You set a threshold in basis points (e.g. 500 = 5%). The app generates a ZK proof that your ROI is ≥ that threshold without revealing `total_in` or `total_out`. Proof is generated in-browser (Noir + Barretenberg); you can see local verification result and proof/public-input details.

5. **Verify on-chain**  
   Uses Garaga’s `getZKHonkCallData` and the deployed verifier contract to run `verify_ultra_keccak_zk_honk_proof` on Starknet. Requires `VITE_VERIFIER_ADDRESS` and the same RPC as the deployed contract (e.g. devnet or testnet).

---

## Building the circuit and deploying the verifier (optional)

If you want to regenerate the circuit artifact and deploy the verifier yourself (e.g. for devnet):

### Toolchain

- **Noir** (e.g. 1.0.0-beta.16): `make install-noir`  
- **Barretenberg** (bb, matching nightly): `make install-barretenberg`  
- **Starknet** (sncast, scarb via asdf): `make install-starknet`  
- **Starknet devnet**: `make install-devnet`  
- **Garaga** (Python 3.10): `make install-garaga`  
- **Scarb / asdf**: `make update-tools`

### Build circuit and verifier

```bash
make build-circuit
make exec-circuit    # witness from Prover.toml
make gen-vk          # may need: make download-crs first
make gen-verifier    # Cairo verifier from Garaga
make build-verifier
```

### Run devnet and deploy

```bash
make devnet          # in one terminal
make accounts-file   # in another
make declare-verifier
make deploy-verifier # use class hash from declare output if different from Makefile
make artifacts       # copy circuit.json, vk.bin, verifier.json into app/src/assets/
```

Set `VITE_VERIFIER_ADDRESS` to the deployed contract address and `VITE_RPC_URL` to `http://127.0.0.1:5050/rpc`, then run the app and use “Verify on-chain.”

---

## Troubleshooting

- **“Contract not found” on Verify on-chain**  
  Verifier not deployed or wrong network. Deploy with `make declare-verifier` and `make deploy-verifier` on the same RPC (e.g. devnet), then set `VITE_VERIFIER_ADDRESS` and `VITE_RPC_URL`.

- **“Failed to fetch” during proof generation**  
  Barretenberg needs the CRS (Common Reference String). The app uses a Vite plugin and `crs-net-fallback.ts` to point to a working CDN. If it still fails, run `make download-crs` so `~/.bb-crs` is populated, then restart the dev server. Ensure no firewall blocks access to the CRS host.

- **MetaMask Snap / “loading chunk” errors**  
  If the Snap fails to load remote assets, the UI suggests using the manual address field and entering a Starknet address directly.

---

## Useful links

- [Noir quickstart](https://noir-lang.org/docs/getting_started/quick_start)
- [Garaga docs](https://garaga.gitbook.io/garaga/deploy-your-snark-verifier-on-starknet/noir)
- [Starknet.js](https://starknetjs.com/docs/guides/intro)
- [Starknet quickstart](https://docs.starknet.io/quick-start/overview/)
- [Sncast 101](https://foundry-rs.github.io/starknet-foundry/starknet/101.html)
- [Cairo book](https://book.cairo-lang.org/)
