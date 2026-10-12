// E2E admission: reserve exact-message fee and authorize account rent BEFORE co-signing.
import type { Transaction } from '@solana/kit';
import { getTokenSize } from '@solana-program/token';
import { CampaignBudget } from './campaign-budget.ts';
import { messageDigest } from './campaign-proof.ts';
import type { FinalizedTransaction } from './campaign-proof.ts';
import { PAYMENT_LEN } from './program.ts';
export interface SponsorBudget {
  reserve(transaction: Transaction, operation: string): Promise<string>;
  observe(id: string, signature: string): Promise<void>;
}
export interface BudgetBackend {
  fee(transaction: Transaction): Promise<bigint>;
  rent(size: number): Promise<bigint>;
  finalized(signature: string): Promise<FinalizedTransaction | null>;
}
export function campaignSponsorship(budget: CampaignBudget, backend: BudgetBackend): SponsorBudget {
  return {
    async reserve(tx, operation) {
      if (!['authorize','capture','refund','void'].includes(operation)) throw Error('unapproved sponsored operation');
      const fee = await backend.fee(tx);
      const rents = operation === 'authorize' ? await Promise.all([backend.rent(PAYMENT_LEN),backend.rent(getTokenSize())]) : [];
      if (fee <= 0n || rents.some(n=>n<=0n)) throw Error('invalid exact-message campaign quote');
      const id = `relay-${messageDigest(tx.messageBytes)}`;
      budget.reserve(id,'sponsorship',messageDigest(tx.messageBytes),{fees:fee,rent:rents.reduce((a,b)=>a+b,0n),browserAllocation:0n});
      return id;
    },
    async observe(id, signature) {
      const proof = await backend.finalized(signature);
      if (proof) await budget.finalize(id,signature,proof);
      // No history, thrown lookup, failed fsync or inconsistent proof retains the ceiling.
    },
  };
}
