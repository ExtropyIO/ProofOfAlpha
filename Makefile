install-bun:
	curl -fsSL https://bun.sh/install | bash

install-noir:
	curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
	noirup --version 1.0.0-beta.16

install-barretenberg:
	curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
	bbup --version 3.0.0-nightly.20251104

install-starknet:
	curl --proto '=https' --tlsv1.2 -sSf https://sh.starkup.dev | sh

install-devnet:
	asdf plugin add starknet-devnet
	asdf install starknet-devnet 0.6.1

install-garaga:
	pip install garaga==1.0.1

install-app-deps:
	cd app && bun install

update-tools:
	asdf install starknet-devnet
	asdf install starknet-foundry
	asdf install scarb

devnet:
	starknet-devnet --accounts=2 --seed=0 --initial-balance=100000000000000000000000

accounts-file:
	curl -s -X POST -H "Content-Type: application/json" \
		--data '{"jsonrpc":"2.0","id":"1","method":"devnet_getPredeployedAccounts"}' http://127.0.0.1:5050/ \
		| python3 -c "import sys,json; r=json.load(sys.stdin); a=r['result'][0]; print(json.dumps({'alpha-sepolia':{'devnet0':{**a,'class_hash':'0xe2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6','deployed':True,'legacy':False,'salt':'0x14','type':'open_zeppelin'}}}, indent=2))" > ./contracts/accounts.json

build-circuit:
	cd circuit && nargo build

exec-circuit:
	cd circuit && nargo execute witness

prove-circuit:
	bb prove --scheme ultra_honk \
		--oracle_hash keccak \
		-b ./circuit/target/circuit.json \
		-w ./circuit/target/witness.gz \
		-k ./circuit/target/vk \
		-o ./circuit/target

# Pre-download CRS to ~/.bb-crs/ so bb does not hit the often-unreachable crs.aztec.network.
# Run this if gen-vk fails with "HTTP request failed for http://crs.aztec.network/g1.dat".
download-crs:
	@mkdir -p $$HOME/.bb-crs && \
	CRS_SIZE=$$((2**25+1)) && CRS_BYTES=$$((CRS_SIZE*64)) && \
	if [ ! -f "$$HOME/.bb-crs/bn254_g1.dat" ] || [ $$(stat -f%z "$$HOME/.bb-crs/bn254_g1.dat" 2>/dev/null || stat -c%s "$$HOME/.bb-crs/bn254_g1.dat" 2>/dev/null) -lt $$CRS_BYTES ]; then \
	  echo "Downloading CRS (bn254 g1, ~128MB)..."; \
	  curl -sf -H "Range: bytes=0-$$((CRS_BYTES-1))" "https://crs.aztec-cdn.foundation/g1.dat" -o "$$HOME/.bb-crs/bn254_g1.dat" || \
	  curl -sf -H "Range: bytes=0-$$((CRS_BYTES-1))" "https://crs.aztec-labs.com/g1.dat" -o "$$HOME/.bb-crs/bn254_g1.dat"; \
	  chmod 444 "$$HOME/.bb-crs/bn254_g1.dat" 2>/dev/null || true; \
	fi && \
	if [ ! -f "$$HOME/.bb-crs/bn254_g2.dat" ]; then \
	  echo "Downloading CRS (bn254 g2)..."; \
	  curl -sf "https://crs.aztec-cdn.foundation/g2.dat" -o "$$HOME/.bb-crs/bn254_g2.dat" || \
	  curl -sf "https://crs.aztec-labs.com/g2.dat" -o "$$HOME/.bb-crs/bn254_g2.dat"; \
	fi && echo "CRS ready in $$HOME/.bb-crs"

gen-vk: download-crs
	bb write_vk --scheme ultra_honk --oracle_hash keccak -b ./circuit/target/circuit.json -o ./circuit/target

gen-verifier:
	cd contracts && garaga gen --system ultra_keccak_zk_honk --vk ../circuit/target/vk --project-name verifier

build-verifier:
	cd contracts/verifier && scarb build

declare-verifier:
	cd contracts && sncast declare --contract-name UltraKeccakZKHonkVerifier

deploy-verifier:
	# TODO: use class hash from the result of the `make declare-verifier` step
	cd contracts && sncast deploy --salt 0x00 --class-hash 0xf0b231261db9afa4c7fdbb25ec4917043933383ee394d44fbe496d8b083ef

artifacts:
	cp ./circuit/target/circuit.json ./app/src/assets/circuit.json
	cp ./circuit/target/vk ./app/src/assets/vk.bin
	cp ./contracts/target/release/verifier_UltraKeccakZKHonkVerifier.contract_class.json ./app/src/assets/verifier.json

run-app:
	cd app && bun run dev
