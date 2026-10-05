// TypeScript mirror of the accepted program ABI in `src/lib.rs`.
// The program source is normative; E2E tests execute these encodings against the built SBF binary.
import {
  AccountRole,
  type Address,
  getAddressDecoder,
  getAddressEncoder,
  getProgramDerivedAddress,
  type Instruction,
} from "@solana/kit";
import { findAssociatedTokenPda, TOKEN_PROGRAM_ADDRESS, ASSOCIATED_TOKEN_PROGRAM_ADDRESS } from "@solana-program/token";
import { SYSTEM_PROGRAM_ADDRESS } from "@solana-program/system";

export { TOKEN_PROGRAM_ADDRESS, ASSOCIATED_TOKEN_PROGRAM_ADDRESS, SYSTEM_PROGRAM_ADDRESS };

/** `ID` in `src/lib.rs`: a local harness identity, not a deployment. */
export const LOCAL_PROGRAM_ID: Address = getAddressDecoder().decode(new Uint8Array(32).fill(42));
export const NATIVE_MINT: Address = "So11111111111111111111111111111111111111112" as Address;
export const SEED = new TextEncoder().encode("auth-capture-v1");
export const DISCRIMINATOR = new TextEncoder().encode("SACPAY01");
export const PAYMENT_LEN = 176;

export const Tag = { authorize: 0, reclaim: 1, capture: 2, void: 3, refund: 4 } as const;
export const DATA_LEN = { authorize: 67, reclaim: 1, capture: 26, void: 17, refund: 25 } as const;

export const U64_MAX = (1n << 64n) - 1n;
export const I64_MAX = (1n << 63n) - 1n;

const addresses = getAddressEncoder();
const addressDecoder = getAddressDecoder();

export type Payment = {
  payer: Address;
  server: Address;
  mint: Address;
  salt: Uint8Array;
  maximum: bigint;
  captureDeadline: bigint;
  refundDeadline: bigint;
  held: bigint;
  refundable: bigint;
};

/** Mirrors `Payment::decode`, including its consistency checks. Returns null when invalid. */
export function decodePayment(data: Uint8Array): Payment | null {
  if (data.length !== PAYMENT_LEN || !bytesEqual(data.subarray(0, 8), DISCRIMINATOR)) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const p: Payment = {
    payer: addressDecoder.decode(data.subarray(8, 40)),
    server: addressDecoder.decode(data.subarray(40, 72)),
    mint: addressDecoder.decode(data.subarray(72, 104)),
    salt: data.slice(104, 136),
    maximum: view.getBigUint64(136, true),
    captureDeadline: view.getBigInt64(144, true),
    refundDeadline: view.getBigInt64(152, true),
    held: view.getBigUint64(160, true),
    refundable: view.getBigUint64(168, true),
  };
  if (
    p.payer === p.server ||
    p.maximum === 0n ||
    p.captureDeadline <= 0n ||
    p.refundDeadline < p.captureDeadline ||
    p.held + p.refundable > p.maximum
  ) {
    return null;
  }
  return p;
}

export async function paymentAddress(program: Address, payer: Address, salt: Uint8Array): Promise<Address> {
  const [address] = await getProgramDerivedAddress({
    programAddress: program,
    seeds: [SEED, addresses.encode(payer), salt],
  });
  return address;
}

export async function ata(owner: Address, mint: Address): Promise<Address> {
  const [address] = await findAssociatedTokenPda({ owner, mint, tokenProgram: TOKEN_PROGRAM_ADDRESS });
  return address;
}

function u64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

function i64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigInt64(0, value, true);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** Wire: authorize=0, version=1, escrow=0, fee=0:u64, salt:32, M:u64, Dc:i64, Dr:i64. */
export function authorizeData(salt: Uint8Array, maximum: bigint, dc: bigint, dr: bigint): Uint8Array {
  return concat(Uint8Array.of(Tag.authorize, 1, 0), u64(0n), salt, u64(maximum), i64(dc), i64(dr));
}

/** Wire: capture=2, amount:u64, releaseRemainder:bool(0/1), expectedH:u64, expectedF:u64. */
export function captureData(amount: bigint, releaseRemainder: boolean, h: bigint, f: bigint): Uint8Array {
  return concat(Uint8Array.of(Tag.capture), u64(amount), Uint8Array.of(releaseRemainder ? 1 : 0), u64(h), u64(f));
}

/** Wire: void=3, expectedH:u64, expectedF:u64. */
export function voidData(h: bigint, f: bigint): Uint8Array {
  return concat(Uint8Array.of(Tag.void), u64(h), u64(f));
}

/** Wire: refund=4, amount:u64, expectedH:u64, expectedF:u64. */
export function refundData(amount: bigint, h: bigint, f: bigint): Uint8Array {
  return concat(Uint8Array.of(Tag.refund), u64(amount), u64(h), u64(f));
}

export type DecodedInstruction =
  | { op: "authorize"; salt: Uint8Array; maximum: bigint; captureDeadline: bigint; refundDeadline: bigint }
  | { op: "reclaim" }
  | { op: "capture"; amount: bigint; releaseRemainder: boolean; expectedHeld: bigint; expectedRefundable: bigint }
  | { op: "void"; expectedHeld: bigint; expectedRefundable: bigint }
  | { op: "refund"; amount: bigint; expectedHeld: bigint; expectedRefundable: bigint };

/** Mirrors `process_instruction` dispatch and the authorize prefix guard. Returns null when the program would reject the data. */
export function decodeInstructionData(data: Uint8Array): DecodedInstruction | null {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  switch (data[0]) {
    case Tag.authorize:
      if (data.length !== DATA_LEN.authorize || data[1] !== 1 || data[2] !== 0 || view.getBigUint64(3, true) !== 0n) {
        return null;
      }
      return {
        op: "authorize",
        salt: data.slice(11, 43),
        maximum: view.getBigUint64(43, true),
        captureDeadline: view.getBigInt64(51, true),
        refundDeadline: view.getBigInt64(59, true),
      };
    case Tag.reclaim:
      return data.length === DATA_LEN.reclaim ? { op: "reclaim" } : null;
    case Tag.capture:
      if (data.length !== DATA_LEN.capture || data[9]! > 1) return null;
      return {
        op: "capture",
        amount: view.getBigUint64(1, true),
        releaseRemainder: data[9] === 1,
        expectedHeld: view.getBigUint64(10, true),
        expectedRefundable: view.getBigUint64(18, true),
      };
    case Tag.void:
      if (data.length !== DATA_LEN.void) return null;
      return { op: "void", expectedHeld: view.getBigUint64(1, true), expectedRefundable: view.getBigUint64(9, true) };
    case Tag.refund:
      if (data.length !== DATA_LEN.refund) return null;
      return {
        op: "refund",
        amount: view.getBigUint64(1, true),
        expectedHeld: view.getBigUint64(9, true),
        expectedRefundable: view.getBigUint64(17, true),
      };
    default:
      return null;
  }
}

/** One expected account slot: exact address plus the exact signer/writable role. */
export type AccountSlot = { address: Address; signer: boolean; writable: boolean };

const slot = (address: Address, signer: boolean, writable: boolean): AccountSlot => ({ address, signer, writable });

export function toInstruction(program: Address, slots: AccountSlot[], data: Uint8Array): Instruction {
  return {
    programAddress: program,
    accounts: slots.map((s) => ({
      address: s.address,
      role: s.signer
        ? s.writable
          ? AccountRole.WRITABLE_SIGNER
          : AccountRole.READONLY_SIGNER
        : s.writable
          ? AccountRole.WRITABLE
          : AccountRole.READONLY,
    })),
    data,
  };
}

/** Accounts: payer(s,w), server, payment(w), mint, payer ATA(w), vault(w), rent funder(s,w), System, classic Token, ATA program. */
export function authorizeAccounts(a: {
  payer: Address;
  server: Address;
  payment: Address;
  mint: Address;
  source: Address;
  vault: Address;
  funder: Address;
}): AccountSlot[] {
  return [
    slot(a.payer, true, true),
    slot(a.server, false, false),
    slot(a.payment, false, true),
    slot(a.mint, false, false),
    slot(a.source, false, true),
    slot(a.vault, false, true),
    slot(a.funder, true, true),
    slot(SYSTEM_PROGRAM_ADDRESS, false, false),
    slot(TOKEN_PROGRAM_ADDRESS, false, false),
    slot(ASSOCIATED_TOKEN_PROGRAM_ADDRESS, false, false),
  ];
}

/** Accounts: server(s), payment(w), mint, vault(w), server ATA(w), payer ATA(w), classic Token. */
export function captureAccounts(a: {
  server: Address;
  payment: Address;
  mint: Address;
  vault: Address;
  serverAta: Address;
  payerAta: Address;
}): AccountSlot[] {
  return [
    slot(a.server, true, false),
    slot(a.payment, false, true),
    slot(a.mint, false, false),
    slot(a.vault, false, true),
    slot(a.serverAta, false, true),
    slot(a.payerAta, false, true),
    slot(TOKEN_PROGRAM_ADDRESS, false, false),
  ];
}

/** Accounts: server(s), payment(w), mint, vault(w), payer ATA(w), classic Token. */
export function voidAccounts(a: {
  server: Address;
  payment: Address;
  mint: Address;
  vault: Address;
  payerAta: Address;
}): AccountSlot[] {
  return [
    slot(a.server, true, false),
    slot(a.payment, false, true),
    slot(a.mint, false, false),
    slot(a.vault, false, true),
    slot(a.payerAta, false, true),
    slot(TOKEN_PROGRAM_ADDRESS, false, false),
  ];
}

/** Accounts: server(s), payment(w), mint, server ATA(w), payer ATA(w), classic Token. */
export function refundAccounts(a: {
  server: Address;
  payment: Address;
  mint: Address;
  serverAta: Address;
  payerAta: Address;
}): AccountSlot[] {
  return [
    slot(a.server, true, false),
    slot(a.payment, false, true),
    slot(a.mint, false, false),
    slot(a.serverAta, false, true),
    slot(a.payerAta, false, true),
    slot(TOKEN_PROGRAM_ADDRESS, false, false),
  ];
}

/** Wire: [1]. Accounts: payer(s), payment(w), mint, vault(w), payer ATA(w), classic Token. Payer-direct only. */
export function reclaimAccounts(a: {
  payer: Address;
  payment: Address;
  mint: Address;
  vault: Address;
  payerAta: Address;
}): AccountSlot[] {
  return [
    slot(a.payer, true, false),
    slot(a.payment, false, true),
    slot(a.mint, false, false),
    slot(a.vault, false, true),
    slot(a.payerAta, false, true),
    slot(TOKEN_PROGRAM_ADDRESS, false, false),
  ];
}
