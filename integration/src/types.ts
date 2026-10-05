// x402 v2 core shapes (specs/x402-specification-v2.md at the UPSTREAM x402 pin) and the
// local SVM auth-capture payloads. The SVM payload fields are proposed local wire rules,
// not an upstream binding.

export type PaymentRequirements = {
  scheme: string;
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra?: Record<string, unknown>;
};

export type PaymentPayload = {
  x402Version: number;
  resource?: unknown;
  accepted: PaymentRequirements;
  payload: Record<string, unknown>;
  extensions?: Record<string, unknown>;
};

export type FacilitatorRequest = {
  x402Version: number;
  paymentPayload: PaymentPayload;
  paymentRequirements: PaymentRequirements;
};

export type VerifyResponse = {
  isValid: boolean;
  invalidReason?: string;
  payer?: string;
  extra?: Record<string, unknown>;
};

export type SettleResponse = {
  success: boolean;
  errorReason?: string;
  payer?: string;
  transaction: string;
  network: string;
  amount?: string;
  extensions?: Record<string, unknown>;
};

/** Facilitator-relayed operations. `reclaim` is payer-direct and never relayed. */
export type Operation = "authorize" | "capture" | "void" | "refund";

/**
 * Operation result reported under `extensions["auth-capture"]` (local wire rule).
 * `amount` is the operation's primary transfer: deposit, capture, release, or refund.
 * `released` is the remainder returned to the payer by capture-and-void.
 */
export type OperationResult = {
  operation: Operation;
  payment: string;
  amount: string;
  releaseRemainder?: boolean;
  released?: string;
  held: string;
  refundable: string;
};

export const SCHEME = "auth-capture";
export const RESULT_KEY = "auth-capture";

export const Reason = {
  x402Version: "invalid_x402_version",
  unsupportedScheme: "unsupported_scheme",
  invalidNetwork: "invalid_network",
  invalidPayload: "invalid_payload",
  invalidRequirements: "invalid_payment_requirements",
  insufficientFunds: "insufficient_funds",
  transactionState: "invalid_transaction_state",
  settlementPending: "settlement_pending",
  unexpectedVerify: "unexpected_verify_error",
  unexpectedSettle: "unexpected_settle_error",
  networkMismatch: "invalid_auth_capture_svm_network_mismatch",
  acceptedMismatch: "invalid_auth_capture_svm_accepted_mismatch",
  paymentFlow: "invalid_auth_capture_svm_unsupported_payment_flow",
  unsupportedExtra: "invalid_auth_capture_svm_unsupported_extra",
  programMismatch: "invalid_auth_capture_svm_program_mismatch",
  feePayerMismatch: "invalid_auth_capture_svm_fee_payer_mismatch",
  unsupportedAsset: "invalid_auth_capture_svm_unsupported_asset",
  deadlineOrdering: "invalid_auth_capture_svm_deadline_ordering",
  payloadType: "invalid_auth_capture_svm_payload_type",
  reclaimNotRelayed: "invalid_auth_capture_svm_reclaim_not_relayed",
  transaction: "invalid_auth_capture_svm_transaction",
  instructions: "invalid_auth_capture_svm_instructions",
  instructionData: "invalid_auth_capture_svm_instruction_data",
  accounts: "invalid_auth_capture_svm_accounts",
  signature: "invalid_auth_capture_svm_signature",
  termsMismatch: "invalid_auth_capture_svm_terms_mismatch",
  payloadMismatch: "invalid_auth_capture_svm_payload_mismatch",
  paymentNotFound: "invalid_auth_capture_svm_payment_not_found",
  paymentExists: "invalid_auth_capture_svm_payment_already_exists",
  unexpectedState: "invalid_auth_capture_svm_unexpected_payment_state",
  captureExpired: "invalid_auth_capture_svm_capture_deadline_expired",
  refundExpired: "invalid_auth_capture_svm_refund_deadline_expired",
  amount: "invalid_auth_capture_svm_amount",
  emptyHold: "invalid_auth_capture_svm_empty_hold",
  tokenAccount: "invalid_auth_capture_svm_token_account",
  /** The server wallet, not the client, cannot fund a refund (`insufficient_funds` is the client's). */
  serverInsufficientFunds: "invalid_auth_capture_svm_server_insufficient_funds",
  /** The vault does not back the stored hold; unreachable while the program's invariants hold. */
  vaultShortfall: "invalid_auth_capture_svm_vault_shortfall",
  simulationFailed: "invalid_auth_capture_svm_simulation_failed",
} as const;

export type ReasonCode = (typeof Reason)[keyof typeof Reason];
