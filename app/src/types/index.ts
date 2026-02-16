export enum ProofState {
  Initial = 'Initial',
  GeneratingWitness = 'Generating witness',
  GeneratingProof = 'Generating proof',
  PreparingCalldata = 'Preparing calldata',
  ConnectingWallet = 'Connecting wallet',
  SendingTransaction = 'Sending transaction',
  ProofVerified = 'Proof is verified'
}

export interface ProofStateData {
  state: ProofState;
  error?: string;
  /** Result of the verifier contract read call (when state is ProofVerified). */
  verificationResult?: boolean;
}
