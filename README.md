<<<<<<< Updated upstream
# ProofOfAlpha
Tool to prove your DeFi track record
=======
# Scaffold Garaga app

This is a Noir+Garaga+Starknet starter with in-browser proving and a step-by-step guide how to:
- Generate and deploy UltraHonk proof verifier contract to Starknet devnet
- Add state to your privacy preserving app
- Add wallet connection and deploy to public testnet

## Install

Ensure you have node.js >= 20 installed.  

Bun is used for package management, install it with:
```sh
make install-bun
```

For compiling Noir circuits and generating proofs we need specific versions of Aztec packages:
```sh
make install-noir
make install-barretenberg
```

Starknet toolkit comes in a single bundle via asdf (the following command will install it if you don't have it):
```sh
make install-starknet
```

We also need to install a tool for spawning local Starknet chain:
```sh
make install-devnet
```

Install Scarb and other asdf tools (required for `make gen-verifier`):
```sh
make update-tools
```

Finally we need to install Garaga. Make sure you have Python 3.10 in your system. You may also need to start a separate Python virtual environment for this to work. You can do that with `python3.10 -m venv garaga-venv && source garaga-venv/bin/activate`. Then install with:

```sh
make install-garaga
```

Note that we need specific versions of Noir, Barretenberg, and Garaga to work well together. If you are experiencing any issues with code generation, proving, and verification — first of all ensure you have the correct package versions.

## Tutorial

This repo is organized in layers: each app iteration is a new git branch.  

Follow the steps and checkout the necessary branch:
1. [`master`](https://github.com/m-kus/scaffold-garaga/tree/master) — in-browser proof generation and stateless proof verification in devnet
2. [`1-app-logic`](https://github.com/m-kus/scaffold-garaga/tree/1-app-logic) — more involved Noir circuit logic
3. [`2-app-state`](https://github.com/m-kus/scaffold-garaga/tree/2-app-state) — extend onchain part with a storage for nullifiers
4. [`3-testnet`](https://github.com/m-kus/scaffold-garaga/tree/3-testnet) — deploy to public Starknet testnet and interact via wallet

## Run app

First of all we need to build our Noir circuit:

```sh
make build-circuit
```

Sample inputs are already provided in `Prover.toml`, execute to generate witness:

```sh
make exec-circuit
```

Generate verification key (this will download the CRS to `~/.bb-crs` if needed):

```sh
make gen-vk
```

If you see `HTTP request failed for http://crs.aztec.network/g1.dat`, run `make download-crs` first to fetch the CRS from the CDN, then run `make gen-vk` again.

Now we can generate the verifier contract in Cairo using Garaga:

```sh
make gen-verifier
```

Let's start our local development network in other terminal instance:

```sh
make devnet
```

You now need to start a new terminal window. Initialize the account we will be using for deployment:

```sh
make accounts-file
```

First we need to declare out contract ("upload" contract code):

```sh
make declare-verifier
```

Now we can instantiate the contract class we obtained (you might need to update the command in Makefile):

```sh
make deploy-verifier
```

Great! Now let's copy necessary artifacts:

```sh
make artifacts
```

Prepare the app and its requirements so you can run it. Go to the `app` folder and:
1. Update the contract address in the app code (change App.tsx). 
1. Make sure you have `tsc` installed. If not, you can install it with `bun add -d typescript@next`.
1. Install vite with `npm install -D vite`
1. Build the app with `bun run build`
1. Finally we can run the app: `bun run dev`

## Phase 1: Data Bridge scaffold

`app/src/services/TransactionFetcher.ts` now contains a frontend service for:
- Pulling swap events from Starknet RPC (per protocol contract + event name)
- Filtering events to a specific user address
- Resolving block timestamps
- Fetching Pragma historical price updates at each timestamp
- Preserving Pragma signatures for ZK circuit inputs

Example:

```ts
import { RpcProvider } from 'starknet';
import { TransactionFetcher } from './services/TransactionFetcher';

const provider = new RpcProvider({ nodeUrl: 'http://127.0.0.1:5050/rpc' });
const fetcher = new TransactionFetcher(
  provider,
  [
    {
      name: 'Jediswap',
      contractAddress: '0x<jediswap_pool_or_router>',
      eventNames: ['Swap'],
      // Update these indexes per protocol ABI:
      userAddressKeyIndices: [1],
      amountInDataIndex: 0,
      amountOutDataIndex: 1,
    },
    {
      name: 'Ekubo',
      contractAddress: '0x<ekubo_contract>',
      eventNames: ['Swap'],
    },
  ],
  {
    baseUrl: 'https://<your-pragma-host>',
    queryParams: {
      // Set based on your Pragma endpoint requirements
      pair: 'ETH/USD',
    },
  },
);

const rows = await fetcher.fetchSwapsWithPragma({
  userAddress: '0x<user_address>',
  fromBlock: 0,
  toBlock: 'latest',
});

// Each row now has swap data + pragma.signature for circuit inputs
console.log(rows);
```

Phase 1.5 UI is wired in `app/src/App.tsx` as a **Data Bridge** panel with:
- Starknet wallet connect button (address auto-selected from wallet)
- block range inputs
- protocol contract inputs (Jediswap + Ekubo)
- Pragma URL + pair
- table output including Pragma signature per row

Optional env vars:
- `VITE_RPC_URL`
- `VITE_JEDISWAP_CONTRACT`
- `VITE_EKUBO_CONTRACT`
- `VITE_PRAGMA_BASE_URL`
- `VITE_PRAGMA_PAIR`
- `VITE_PRAGMA_API_KEY`

## Deploy verifier to devnet (fix "Contract not found")

If you see **Contract not found** when sending the transaction, the verifier is not deployed on your devnet. With devnet already running (`make devnet`), in **another terminal** run:

```sh
make accounts-file
make declare-verifier
```

If the Makefile’s `deploy-verifier` target has a different class hash than the one printed by `declare-verifier`, edit `Makefile` and set `--class-hash` in `deploy-verifier` to the printed `contract_class_hash`. Then:

```sh
make deploy-verifier
```

Copy the **contract_address** from the output and either:

- Set it when starting the app: `VITE_VERIFIER_ADDRESS=0x<your_address> bun run dev`, or  
- Put `VITE_VERIFIER_ADDRESS=0x<your_address>` in `app/.env` and run `bun run dev`.

Then run the proof flow again in the app.

## Troubleshooting

**"Failed to fetch" at "Generating proof"** — Proof generation needs a CRS (Common Reference String) from the network. The app rewrites the default CRS host to a more reliable CDN in two ways: (1) a Vite plugin in `app/vite.config.ts` that replaces `crs.aztec.network` with `crs.aztec-cdn.foundation` when bundling, and (2) a direct patch in `app/node_modules/@aztec/bb.js/dest/browser/crs/net_crs.js` (re-run the same URL replacements after `bun install` if the error returns). Restart the dev server after any change. If the error persists, check network/firewall or try again later.

## Useful links

- Noir quickstart https://noir-lang.org/docs/getting_started/quick_start
- Garaga docs https://garaga.gitbook.io/garaga/deploy-your-snark-verifier-on-starknet/noir
- Starknet.js docs https://starknetjs.com/docs/guides/intro
- Starknet quickstart https://docs.starknet.io/quick-start/overview/
- Sncast 101 https://foundry-rs.github.io/starknet-foundry/starknet/101.html
- Cairo book https://book.cairo-lang.org/
>>>>>>> Stashed changes
