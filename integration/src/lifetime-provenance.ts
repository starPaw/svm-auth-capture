// Additive evidence only. Neither an observation nor a canonical origin grants payment,
// receipt or recovery authority. Lifetime is retained from the original message preparation.
import { createHmac, timingSafeEqual } from "node:crypto";
import { getCompiledTransactionMessageDecoder, isAddress, type Transaction } from "@solana/kit";
import { messageHash } from "./submission-journal.ts";
import { isObject } from "./types.ts";

export const LIFETIME_EXTENSION = "auth-capture-lifetime";
export type LifetimeObservation = {
  version: 1;
  messageHash: string;
  blockhash: string;
  lastValidBlockHeight: string;
  /** RPC response context, only a candidate for an origin check. */
  contextSlot: string | null;
  commitment: "processed" | "confirmed" | "finalized" | null;
  network: string | null;
  genesisHash: string | null;
};
export type ObservationTransport = { observation: LifetimeObservation; attestation?: string };
export type CanonicalOrigin =
  | { state: "verified"; blockhash: string; slot: string; commitment: "finalized"; network: string; genesisHash: string }
  | { state: "unverified"; reason: "missing-observation" | "invalid-observation" | "binding-mismatch" | "network-mismatch" | "origin-unavailable" | "lookup-unavailable" };
export type RelayProvenance = {
  version: 1;
  messageHash: string;
  blockhash: string;
  observation: { state: "recorded"; source: "first-party" | "request"; value: LifetimeObservation }
    | { state: "unavailable"; reason: "missing" | "invalid" | "binding-mismatch" };
  origin: CanonicalOrigin;
};
/** Strip all caller labels/MACs; supplied metadata never becomes a first-party attestation. */
export function requestObservation(extensions: unknown): { observation: unknown } | undefined {
  if (!isObject(extensions) || !Object.hasOwn(extensions, LIFETIME_EXTENSION)) return undefined;
  const transport = extensions[LIFETIME_EXTENSION];
  return { observation: isObject(transport) ? transport.observation : undefined };
}

export interface OriginReader {
  /** One candidate, pinned genesis + matching finalized block, one absolute deadline. */
  verifyBlockhashOrigin(blockhash: string, candidateSlot: bigint, genesisHash: string, network: string): Promise<CanonicalOrigin>;
}

const U64_MAX = (1n << 64n) - 1n;
export function isU64Decimal(value: unknown): value is string {
  return typeof value === "string" && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= U64_MAX;
}
export function parseObservation(value: unknown): LifetimeObservation | undefined {
  if (!isObject(value) || value.version !== 1 ||
      Object.keys(value).sort().join(",") !== "blockhash,commitment,contextSlot,genesisHash,lastValidBlockHeight,messageHash,network,version" ||
      typeof value.messageHash !== "string" || !/^[a-f0-9]{64}$/.test(value.messageHash) ||
      typeof value.blockhash !== "string" || !isAddress(value.blockhash) || !isU64Decimal(value.lastValidBlockHeight) ||
      !(value.contextSlot === null || isU64Decimal(value.contextSlot)) ||
      ![null, "processed", "confirmed", "finalized"].includes(value.commitment as never) ||
      !(value.network === null || (typeof value.network === "string" && /^solana:[1-9A-HJ-NP-Za-km-z]{32}$/.test(value.network))) ||
      !(value.genesisHash === null || (typeof value.genesisHash === "string" && isAddress(value.genesisHash)))) return undefined;
  // Copy allowlisted scalars: later caller mutation cannot alter a retained observation.
  return { version: 1, messageHash: value.messageHash, blockhash: value.blockhash,
    lastValidBlockHeight: value.lastValidBlockHeight, contextSlot: value.contextSlot,
    commitment: value.commitment, network: value.network, genesisHash: value.genesisHash } as LifetimeObservation;
}

const observations = new WeakMap<Transaction, LifetimeObservation>();
export function retainObservation(transaction: Transaction, lifetime: {
  blockhash: string; lastValidBlockHeight: bigint; contextSlot?: bigint;
  commitment?: "processed" | "confirmed" | "finalized"; network?: string; genesisHash?: string;
}): void {
  const value = parseObservation({ version: 1, messageHash: messageHash(transaction.messageBytes),
    blockhash: lifetime.blockhash, lastValidBlockHeight: lifetime.lastValidBlockHeight.toString(),
    contextSlot: lifetime.contextSlot?.toString() ?? null, commitment: lifetime.commitment ?? null,
    network: lifetime.network ?? null, genesisHash: lifetime.genesisHash ?? null });
  if (value) observations.set(transaction, value);
}
export function transactionObservation(transaction: Transaction): LifetimeObservation | undefined {
  const value = observations.get(transaction);
  return value && parseObservation(value);
}
export function matchesObservation(value: LifetimeObservation, transaction: Transaction): boolean {
  return value.messageHash === messageHash(transaction.messageBytes) &&
    value.blockhash === getCompiledTransactionMessageDecoder().decode(transaction.messageBytes).lifetimeToken;
}
function authenticationBytes(value: LifetimeObservation): string {
  // Fixed order and domain separate this evidence MAC from bearer authentication and wire signing.
  return "svm-auth-capture:relay-lifetime:v1\n" + JSON.stringify([
    value.version, value.messageHash, value.blockhash, value.lastValidBlockHeight,
    value.contextSlot, value.commitment, value.network, value.genesisHash,
  ]);
}
export function attestObservation(value: LifetimeObservation, key: string): ObservationTransport {
  return { observation: value, attestation: createHmac("sha256", key).update(authenticationBytes(value)).digest("hex") };
}
function authenticated(value: LifetimeObservation, attestation: unknown, key?: string): boolean {
  if (!key || typeof attestation !== "string" || !/^[a-f0-9]{64}$/.test(attestation)) return false;
  const expected = createHmac("sha256", key).update(authenticationBytes(value)).digest();
  return timingSafeEqual(expected, Buffer.from(attestation, "hex"));
}

export async function relayProvenance(transaction: Transaction, transport: unknown, network: string,
  reader?: OriginReader, key?: string): Promise<RelayProvenance> {
  const base = { version: 1 as const, messageHash: messageHash(transaction.messageBytes),
    blockhash: getCompiledTransactionMessageDecoder().decode(transaction.messageBytes).lifetimeToken };
  const unavailable = (reason: "missing" | "invalid" | "binding-mismatch"): RelayProvenance => ({ ...base,
    observation: { state: "unavailable", reason }, origin: { state: "unverified",
      reason: reason === "missing" ? "missing-observation" : reason === "invalid" ? "invalid-observation" : "binding-mismatch" } });
  if (transport === undefined) return unavailable("missing");
  const value = isObject(transport) ? parseObservation(transport.observation) : undefined;
  if (!value) return unavailable("invalid");
  if (!matchesObservation(value, transaction)) return unavailable("binding-mismatch");
  const observation = { state: "recorded" as const,
    source: authenticated(value, (transport as Record<string, unknown>).attestation, key) ? "first-party" as const : "request" as const, value };
  const unverified = (reason: Extract<CanonicalOrigin, { state: "unverified" }>["reason"]): RelayProvenance =>
    ({ ...base, observation, origin: { state: "unverified", reason } });
  if (value.network !== network || !value.genesisHash || network !== `solana:${value.genesisHash.slice(0, 32)}`) return unverified("network-mismatch");
  if (value.contextSlot === null) return unverified("origin-unavailable");
  if (!reader) return unverified("lookup-unavailable");
  try {
    const origin = await reader.verifyBlockhashOrigin(value.blockhash, BigInt(value.contextSlot), value.genesisHash, network);
    // Do not accept a reader's unrelated proof; the production reader also checks pinned genesis.
    if (origin.state === "verified" && (origin.blockhash !== base.blockhash || origin.slot !== value.contextSlot ||
        origin.genesisHash !== value.genesisHash || origin.network !== network || origin.commitment !== "finalized")) return unverified("binding-mismatch");
    return { ...base, observation, origin };
  } catch { return unverified("lookup-unavailable"); }
}
