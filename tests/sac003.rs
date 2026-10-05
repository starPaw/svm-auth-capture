//! All acceptance assertions execute the compiled SBF program in LiteSVM.
use litesvm::{
    types::{FailedTransactionMetadata, TransactionResult},
    LiteSVM,
};
use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::{AccountMeta, Instruction},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction, system_program,
    transaction::{Transaction, TransactionError},
};
use spl_token::state::{Account as TokenAccount, Mint};
use svm_auth_capture::{
    authorize_data, capture_data, payment_address, refund_data, void_data, Payment, ID, PAYMENT_LEN,
};

const NOW: i64 = 1_000;
const DC: i64 = 1_100;
const DR: i64 = 1_200;
const M: u64 = 100;

struct Fixture {
    svm: LiteSVM,
    payer: Keypair,
    sponsor: Keypair,
    server: Keypair,
    outsider: Keypair,
    mint: Pubkey,
    payment: Pubkey,
    source: Pubkey,
    vault: Pubkey,
    salt: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        let mut svm = LiteSVM::new().with_sigverify(true);
        // Fail loudly if the binary is missing; never substitute a native processor.
        svm.add_program_from_file(ID, "target/deploy/svm_auth_capture.so")
            .unwrap();
        let payer = Keypair::new();
        let sponsor = Keypair::new();
        let server = Keypair::new();
        let outsider = Keypair::new();
        for key in [&payer, &sponsor, &outsider] {
            svm.airdrop(&key.pubkey(), 10_000_000_000).unwrap();
        }
        let mint_key = Keypair::new();
        let mint = mint_key.pubkey();
        let source = ata(&payer.pubkey(), &mint);
        let setup = vec![
            system_instruction::create_account(
                &sponsor.pubkey(),
                &mint,
                svm.minimum_balance_for_rent_exemption(Mint::LEN),
                Mint::LEN as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_mint2(
                &spl_token::id(),
                &mint,
                &payer.pubkey(),
                Some(&payer.pubkey()),
                6,
            )
            .unwrap(),
            create_ata(&sponsor.pubkey(), &payer.pubkey(), &mint),
            create_ata(&sponsor.pubkey(), &server.pubkey(), &mint),
            spl_token::instruction::mint_to(
                &spl_token::id(),
                &mint,
                &source,
                &payer.pubkey(),
                &[],
                1_000,
            )
            .unwrap(),
        ];
        let tx = Transaction::new_signed_with_payer(
            &setup,
            Some(&sponsor.pubkey()),
            &[&sponsor, &payer, &mint_key],
            svm.latest_blockhash(),
        );
        svm.send_transaction(tx).unwrap();
        let salt = [7; 32];
        let payment = payment_address(&ID, &payer.pubkey(), &salt).0;
        let vault = ata(&payment, &mint);
        let mut f = Self {
            svm,
            payer,
            sponsor,
            server,
            outsider,
            mint,
            payment,
            source,
            vault,
            salt,
        };
        f.time(NOW);
        f
    }

    fn time(&mut self, unix_timestamp: i64) {
        let mut clock = self.svm.get_sysvar::<Clock>();
        clock.unix_timestamp = unix_timestamp;
        self.svm.set_sysvar(&clock);
        assert_eq!(
            self.svm.get_sysvar::<Clock>().unix_timestamp,
            unix_timestamp
        );
    }

    fn authorize(&self) -> Instruction {
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.server.pubkey(), false),
                AccountMeta::new(self.payment, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(self.source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new(self.sponsor.pubkey(), true),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(
                    spl_associated_token_account_client::program::id(),
                    false,
                ),
            ],
            data: authorize_data(self.salt, M, DC, DR),
        }
    }

    fn reclaim(&self) -> Instruction {
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new_readonly(self.payer.pubkey(), true),
                AccountMeta::new(self.payment, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new(self.source, false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data: vec![1],
        }
    }

    // Every call uses a fresh blockhash: retry assertions reach program guards.
    // The sponsor pays fees; it is never an economic authority.
    #[allow(clippy::result_large_err)] // Preserve the harness's native error/log metadata.
    fn send(&mut self, instructions: &[Instruction], signer: Option<u8>) -> TransactionResult {
        self.svm.expire_blockhash();
        let mut signers = vec![&self.sponsor];
        match signer {
            Some(0) => signers.push(&self.payer),
            Some(1) => signers.push(&self.server),
            Some(2) => signers.push(&self.outsider),
            None => {}
            _ => panic!("unknown fixture signer"),
        }
        let tx = Transaction::new_signed_with_payer(
            instructions,
            Some(&self.sponsor.pubkey()),
            &signers,
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx)
    }

    fn amount(&self, address: Pubkey) -> u64 {
        self.svm
            .get_account(&address)
            .map(|a| TokenAccount::unpack(&a.data).unwrap().amount)
            .unwrap_or(0)
    }

    fn state(&self) -> Payment {
        let account = self.svm.get_account(&self.payment).unwrap();
        assert_eq!(account.owner, ID);
        assert_eq!(account.data.len(), PAYMENT_LEN);
        Payment::decode(&account.data).unwrap()
    }

    fn account_snapshot(&self) -> Vec<(Pubkey, Option<Account>)> {
        [
            self.payment,
            self.source,
            ata(&self.server.pubkey(), &self.mint),
            self.vault,
            self.mint,
            self.payer.pubkey(),
            self.server.pubkey(),
            self.outsider.pubkey(),
        ]
        .into_iter()
        .map(|key| (key, self.svm.get_account(&key)))
        .collect()
    }

    fn fails(
        &mut self,
        instructions: &[Instruction],
        signer: Option<u8>,
    ) -> FailedTransactionMetadata {
        let before = self.account_snapshot();
        let sol_before = self.svm.get_balance(&self.sponsor.pubkey()).unwrap();
        let err = self
            .send(instructions, signer)
            .expect_err("must reject in actual SVM execution");
        assert!(
            matches!(err.err, TransactionError::InstructionError(..)),
            "{err:?}"
        );
        assert!(
            err.meta
                .logs
                .iter()
                .any(|s| s.contains(&format!("Program {ID} invoke"))),
            "{err:?}"
        );
        assert_eq!(
            self.account_snapshot(),
            before,
            "failed tx must preserve all payment/token state"
        );
        let fee = if signer.is_some() { 10_000 } else { 5_000 };
        assert_eq!(
            sol_before - self.svm.get_balance(&self.sponsor.pubkey()).unwrap(),
            fee,
            "failed transaction SOL fee is separate from held tokens/rent"
        );
        err
    }

    fn authorized(&mut self) {
        let ix = self.authorize();
        self.send(&[ix], Some(0)).unwrap();
        assert_eq!(self.amount(self.source), 1_000 - M);
        assert_eq!(
            self.state(),
            Payment {
                payer: self.payer.pubkey(),
                server: self.server.pubkey(),
                mint: self.mint,
                salt: self.salt,
                maximum: M,
                capture_deadline: DC,
                refund_deadline: DR,
                held: M,
                refundable: 0
            }
        );
    }

    fn capture(&self, amount: u64, release: bool, h: u64, f: u64) -> Instruction {
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new_readonly(self.server.pubkey(), true),
                AccountMeta::new(self.payment, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new(ata(&self.server.pubkey(), &self.mint), false),
                AccountMeta::new(self.source, false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data: capture_data(amount, release, h, f),
        }
    }

    fn void(&self, h: u64, f: u64) -> Instruction {
        let mut ix = self.capture(1, false, h, f);
        ix.accounts.remove(4);
        ix.data = void_data(h, f);
        ix
    }

    fn funded() -> Self {
        let mut f = Self::new();
        f.authorized();
        f
    }

    fn balances(&self, h: u64, captured: u64, server_paid: u64, returned: u64, surplus: u64) {
        let expected = Payment {
            payer: self.payer.pubkey(),
            server: self.server.pubkey(),
            mint: self.mint,
            salt: self.salt,
            maximum: M,
            capture_deadline: DC,
            refund_deadline: DR,
            held: h,
            refundable: captured,
        };
        assert_eq!(self.state(), expected, "balances and every immutable term");
        assert!(h.checked_add(captured).unwrap() <= M);
        assert_eq!(self.amount(self.vault), h + surplus);
        assert_eq!(self.amount(self.source), 1_000 - M + returned);
        assert_eq!(
            self.amount(ata(&self.server.pubkey(), &self.mint)),
            server_paid
        );
    }

    fn prepare(&mut self, ix: &Instruction, server: bool) -> Transaction {
        self.svm.expire_blockhash();
        Transaction::new_signed_with_payer(
            std::slice::from_ref(ix),
            Some(&self.sponsor.pubkey()),
            &[
                &self.sponsor,
                if server { &self.server } else { &self.payer },
            ],
            self.svm.latest_blockhash(),
        )
    }

    fn freeze(&mut self, key: Pubkey, frozen: bool) {
        let ix = if frozen {
            spl_token::instruction::freeze_account(
                &spl_token::id(),
                &key,
                &self.mint,
                &self.payer.pubkey(),
                &[],
            )
        } else {
            spl_token::instruction::thaw_account(
                &spl_token::id(),
                &key,
                &self.mint,
                &self.payer.pubkey(),
                &[],
            )
        }
        .unwrap();
        self.send(&[ix], Some(0)).unwrap();
    }

    fn edit_token(&mut self, key: Pubkey, change: impl FnOnce(&mut TokenAccount)) {
        // Adversarial account fixtures only; transitions still execute real SBF/Token CPIs.
        let mut account = self.svm.get_account(&key).unwrap();
        let mut state = TokenAccount::unpack(&account.data).unwrap();
        change(&mut state);
        TokenAccount::pack(state, &mut account.data).unwrap();
        self.svm.set_account(key, account).unwrap();
    }
}

#[test]
fn repeated_refunds_exact_deltas_bounds_and_terminal_zero() {
    let mut f = Fixture::funded();
    f.send(&[f.capture(60, false, 100, 0)], Some(1)).unwrap();
    f.balances(40, 60, 60, 0, 0);
    f.check(40, 60, 60, 900, 0);
    f.send(&[f.refund(10, 40, 60)], Some(1)).unwrap();
    f.check(40, 50, 50, 910, 0);
    f.send(&[f.refund(20, 40, 50)], Some(1)).unwrap();
    f.check(40, 30, 30, 930, 0);
    for amount in [0, 31, u64::MAX] {
        invalid_argument(&f.fails(&[f.refund(amount, 40, 30)], Some(1)));
    }
    f.send(&[f.refund(30, 40, 30)], Some(1)).unwrap();
    f.check(40, 0, 0, 960, 0);
    invalid_argument(&f.fails(&[f.refund(1, 40, 0)], Some(1)));
    f.check(40, 0, 0, 960, 0);
    // F=0 does not close the hold; later capture can create new refundable value.
    f.send(&[f.capture(20, false, 40, 0)], Some(1)).unwrap();
    f.check(20, 20, 20, 960, 0);
}

#[test]
fn exact_pair_and_fresh_byte_replay_are_required() {
    let mut f = Fixture::funded();
    f.send(&[f.capture(50, false, 100, 0)], Some(1)).unwrap();
    for (h, refundable) in [(49, 50), (50, 49)] {
        invalid_argument(&f.fails(&[f.refund(10, h, refundable)], Some(1)));
    }
    let ix = f.refund(10, 50, 50);
    f.send(std::slice::from_ref(&ix), Some(1)).unwrap();
    // send expires the blockhash and re-signs; this reaches the pair guard.
    invalid_argument(&f.fails(&[ix], Some(1)));
    f.check(50, 40, 40, 910, 0);
}

#[test]
fn server_signature_and_signed_refund_bytes_cannot_be_substituted() {
    let mut f = Fixture::funded();
    f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
    let ix = f.refund(10, 70, 30);
    let mut missing = ix.clone();
    missing.accounts[0].is_signer = false;
    assert_eq!(
        f.fails(&[missing], None).err,
        TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::MissingRequiredSignature
        )
    );
    for (key, signer) in [
        (f.payer.pubkey(), Some(0)),
        (f.sponsor.pubkey(), None),
        (f.outsider.pubkey(), Some(2)),
    ] {
        let mut wrong = ix.clone();
        wrong.accounts[0] = AccountMeta::new_readonly(key, true);
        invalid_argument(&f.fails(&[wrong], signer));
    }
    let mut unsigned =
        Transaction::new_with_payer(std::slice::from_ref(&ix), Some(&f.sponsor.pubkey()));
    unsigned.partial_sign(&[&f.sponsor], f.svm.latest_blockhash());
    let before = f.account_snapshot();
    let sol = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
    assert_eq!(
        f.svm.send_transaction(unsigned).unwrap_err().err,
        TransactionError::SignatureFailure
    );
    assert_eq!(f.account_snapshot(), before);
    assert_eq!(f.svm.get_balance(&f.sponsor.pubkey()).unwrap(), sol);
    for byte in [1, 9, 17] {
        let mut tx = f.prepare(&ix, true);
        tx.message.instructions[0].data[byte] ^= 1;
        tx.signatures[0] = f.sponsor.sign_message(&tx.message_data());
        let before = f.account_snapshot();
        let sol = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
        assert_eq!(
            f.svm.send_transaction(tx).unwrap_err().err,
            TransactionError::SignatureFailure
        );
        assert_eq!(f.account_snapshot(), before);
        assert_eq!(f.svm.get_balance(&f.sponsor.pubkey()).unwrap(), sol);
    }
    f.check(70, 30, 30, 900, 0);
}

#[test]
fn refund_account_roles_and_fixed_token_program_are_enforced() {
    let mut f = Fixture::funded();
    f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
    f.send(
        &[create_ata(
            &f.sponsor.pubkey(),
            &f.outsider.pubkey(),
            &f.mint,
        )],
        None,
    )
    .unwrap();
    let ix = f.refund(10, 70, 30);
    for index in [3, 4] {
        let mut wrong = ix.clone();
        wrong.accounts[index].pubkey = ata(&f.outsider.pubkey(), &f.mint);
        f.fails(&[wrong], Some(1));
    }
    for index in [3, 4] {
        let mut wrong = ix.clone();
        wrong.accounts[index].pubkey = Pubkey::new_unique(); // missing account
        f.fails(&[wrong], Some(1));
    }
    let mut wrong_program = ix.clone();
    wrong_program.accounts[5].pubkey = system_program::id();
    f.fails(&[wrong_program], Some(1));
    // Canonical address alone is insufficient after a real Token owner reassignment.
    let source = ata(&f.server.pubkey(), &f.mint);
    let change = spl_token::instruction::set_authority(
        &spl_token::id(),
        &source,
        Some(&f.outsider.pubkey()),
        spl_token::instruction::AuthorityType::AccountOwner,
        &f.server.pubkey(),
        &[],
    )
    .unwrap();
    f.send(&[change], Some(1)).unwrap();
    f.fails(&[ix], Some(1));
    f.check(70, 30, 30, 900, 0);
}

#[test]
fn wrong_mint_and_reassigned_payer_destination_fail() {
    for source_wrong in [false, true] {
        let mut f = Fixture::funded();
        f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
        let key = if source_wrong {
            ata(&f.server.pubkey(), &f.mint)
        } else {
            f.source
        };
        f.edit_token(key, |state| state.mint = Pubkey::new_unique());
        f.fails(&[f.refund(10, 70, 30)], Some(1));
        f.check(70, 30, 30, 900, 0);
    }
    let mut f = Fixture::funded();
    f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
    let change = spl_token::instruction::set_authority(
        &spl_token::id(),
        &f.source,
        Some(&f.outsider.pubkey()),
        spl_token::instruction::AuthorityType::AccountOwner,
        &f.payer.pubkey(),
        &[],
    )
    .unwrap();
    f.send(&[change], Some(0)).unwrap();
    f.fails(&[f.refund(10, 70, 30)], Some(1));
    f.check(70, 30, 30, 900, 0);
}

#[test]
fn refund_uses_execution_time_and_strict_dr_boundary() {
    for time in [DR - 1, DR, DR + 1] {
        let mut f = Fixture::funded();
        f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
        f.time(time);
        let ix = f.refund(10, 70, 30);
        if time < DR {
            f.send(&[ix], Some(1)).unwrap();
            f.check(70, 20, 20, 910, 0);
        } else {
            invalid_argument(&f.fails(&[ix], Some(1)));
            f.check(70, 30, 30, 900, 0);
        }
    }
    let mut f = Fixture::funded();
    f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
    f.time(DR - 1);
    let tx = f.prepare(&f.refund(10, 70, 30), true);
    let before = f.account_snapshot();
    let sol = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
    f.time(DR);
    invalid_argument(&f.svm.send_transaction(tx).unwrap_err());
    assert_eq!(f.account_snapshot(), before);
    assert_eq!(
        sol - f.svm.get_balance(&f.sponsor.pubkey()).unwrap(),
        10_000
    );
    f.check(70, 30, 30, 900, 0);
}

#[test]
fn prepared_refund_refund_race_serializes_in_both_orders() {
    for reverse in [false, true] {
        let mut f = Fixture::funded();
        f.send(&[f.capture(50, false, 100, 0)], Some(1)).unwrap();
        f.svm.expire_blockhash();
        let mut txs: Vec<_> = [f.refund(10, 50, 50), f.refund(20, 50, 50)]
            .iter()
            .map(|ix| {
                Transaction::new_signed_with_payer(
                    std::slice::from_ref(ix),
                    Some(&f.sponsor.pubkey()),
                    &[&f.sponsor, &f.server],
                    f.svm.latest_blockhash(),
                )
            })
            .collect();
        if reverse {
            txs.reverse();
        }
        f.svm.send_transaction(txs.remove(0)).unwrap();
        let before = f.account_snapshot();
        let sol = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
        invalid_argument(&f.svm.send_transaction(txs.remove(0)).unwrap_err());
        assert_eq!(f.account_snapshot(), before);
        assert_eq!(
            sol - f.svm.get_balance(&f.sponsor.pubkey()).unwrap(),
            10_000
        );
        let refunded = if reverse { 20 } else { 10 };
        f.check(50, 50 - refunded, 50 - refunded, 900 + refunded, 0);
    }
}

#[test]
fn prepared_refund_capture_race_serializes_in_both_orders() {
    for capture_first in [false, true] {
        let mut f = Fixture::funded();
        f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
        f.svm.expire_blockhash();
        let refund = f.refund(10, 70, 30);
        let capture = f.capture(20, false, 70, 30);
        let mut txs: Vec<_> = [refund, capture]
            .iter()
            .map(|ix| {
                Transaction::new_signed_with_payer(
                    std::slice::from_ref(ix),
                    Some(&f.sponsor.pubkey()),
                    &[&f.sponsor, &f.server],
                    f.svm.latest_blockhash(),
                )
            })
            .collect();
        if capture_first {
            txs.reverse();
        }
        f.svm.send_transaction(txs.remove(0)).unwrap();
        let before = f.account_snapshot();
        let sol = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
        invalid_argument(&f.svm.send_transaction(txs.remove(0)).unwrap_err());
        assert_eq!(f.account_snapshot(), before);
        assert_eq!(
            sol - f.svm.get_balance(&f.sponsor.pubkey()).unwrap(),
            10_000
        );
        if capture_first {
            f.check(50, 50, 50, 900, 0);
        } else {
            f.check(70, 20, 20, 910, 0);
        }
    }
}

#[test]
fn refund_capture_recurrence_restores_f_but_not_h_and_rejects_stale_pair() {
    let mut f = Fixture::funded();
    f.send(&[f.capture(50, false, 100, 0)], Some(1)).unwrap();
    f.check(50, 50, 50, 900, 0);
    let stale = f.refund(10, 50, 50);
    f.send(&[f.refund(20, 50, 50)], Some(1)).unwrap();
    f.check(50, 30, 30, 920, 0);
    f.send(&[f.capture(20, false, 50, 30)], Some(1)).unwrap();
    f.check(30, 50, 50, 920, 0);
    invalid_argument(&f.fails(&[stale], Some(1)));
    f.send(&[f.refund(10, 30, 50)], Some(1)).unwrap();
    f.check(30, 40, 40, 930, 0);
}

#[test]
fn insufficient_server_liquidity_is_token_cpi_failure_then_retryable() {
    let mut f = Fixture::funded();
    f.send(&[f.capture(50, false, 100, 0)], Some(1)).unwrap();
    f.send(
        &[create_ata(
            &f.sponsor.pubkey(),
            &f.outsider.pubkey(),
            &f.mint,
        )],
        None,
    )
    .unwrap();
    let server_ata = ata(&f.server.pubkey(), &f.mint);
    let outsider_ata = ata(&f.outsider.pubkey(), &f.mint);
    let drain = spl_token::instruction::transfer_checked(
        &spl_token::id(),
        &server_ata,
        &f.mint,
        &outsider_ata,
        &f.server.pubkey(),
        &[],
        40,
        6,
    )
    .unwrap();
    f.send(&[drain], Some(1)).unwrap();
    f.check(50, 50, 10, 900, 0);
    let ix = f.refund(20, 50, 50);
    let err = f.fails(std::slice::from_ref(&ix), Some(1));
    assert!(err
        .meta
        .logs
        .iter()
        .any(|s| s.contains("Instruction: TransferChecked")));
    f.check(50, 50, 10, 900, 0);
    let replenish = spl_token::instruction::mint_to(
        &spl_token::id(),
        &f.mint,
        &server_ata,
        &f.payer.pubkey(),
        &[],
        20,
    )
    .unwrap();
    f.send(&[replenish], Some(0)).unwrap();
    f.send(&[ix], Some(1)).unwrap();
    f.check(50, 30, 10, 920, 0);
}

#[test]
fn frozen_source_or_destination_fails_at_token_cpi_and_same_pair_retries() {
    for frozen_source in [false, true] {
        let mut f = Fixture::funded();
        f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
        let key = if frozen_source {
            ata(&f.server.pubkey(), &f.mint)
        } else {
            f.source
        };
        f.freeze(key, true);
        let ix = f.refund(10, 70, 30);
        let err = f.fails(std::slice::from_ref(&ix), Some(1));
        assert!(err
            .meta
            .logs
            .iter()
            .any(|s| s.contains("Instruction: TransferChecked")));
        f.check(70, 30, 30, 900, 0);
        f.freeze(key, false);
        f.send(&[ix], Some(1)).unwrap();
        f.check(70, 20, 20, 910, 0);
    }
}

#[test]
fn refund_after_void_or_reclaim_preserves_vault_identity_and_surplus() {
    for reclaim in [false, true] {
        let mut f = Fixture::funded();
        let payment_account = f.svm.get_account(&f.payment).unwrap();
        let vault_account = f.svm.get_account(&f.vault).unwrap();
        let donate = spl_token::instruction::transfer_checked(
            &spl_token::id(),
            &f.source,
            &f.mint,
            &f.vault,
            &f.payer.pubkey(),
            &[],
            9,
            6,
        )
        .unwrap();
        f.send(&[donate], Some(0)).unwrap();
        f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
        if reclaim {
            f.time(DC);
            f.send(&[f.reclaim()], Some(0)).unwrap();
        } else {
            f.send(&[f.void(70, 30)], Some(1)).unwrap();
        }
        f.check(0, 30, 30, 961, 9);
        f.send(&[f.refund(10, 0, 30)], Some(1)).unwrap();
        f.check(0, 20, 20, 971, 9);
        f.fails(&[f.authorize()], Some(0));
        let after_payment = f.svm.get_account(&f.payment).unwrap();
        let after_vault = f.svm.get_account(&f.vault).unwrap();
        assert_eq!(after_payment.lamports, payment_account.lamports);
        assert_eq!(after_payment.data.len(), payment_account.data.len());
        assert_eq!(after_vault.lamports, vault_account.lamports);
        assert_eq!(after_vault.owner, vault_account.owner);
    }
}

#[test]
fn malformed_refund_wire_is_rejected() {
    let mut f = Fixture::funded();
    f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
    let mut short = f.refund(10, 70, 30);
    short.data.pop();
    f.fails(&[short], Some(1));
    let mut long = f.refund(10, 70, 30);
    long.data.push(0);
    f.fails(&[long], Some(1));
}

#[test]
fn full_capture_can_be_refunded_without_reopening_hold() {
    let mut f = Fixture::funded();
    f.send(&[f.capture(100, false, 100, 0)], Some(1)).unwrap();
    f.check(0, 100, 100, 900, 0);
    f.send(&[f.refund(40, 0, 100)], Some(1)).unwrap();
    f.check(0, 60, 60, 940, 0);
    invalid_argument(&f.fails(&[f.capture(1, false, 0, 60)], Some(1)));
    invalid_argument(&f.fails(&[f.void(0, 60)], Some(1)));
    f.check(0, 60, 60, 940, 0);
}

#[test]
fn destination_amount_overflow_rolls_back_refund() {
    let mut f = Fixture::funded();
    f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
    f.edit_token(f.source, |state| state.amount = u64::MAX);
    f.fails(&[f.refund(10, 70, 30)], Some(1));
    assert_eq!(f.state().held, 70);
    assert_eq!(f.state().refundable, 30);
    assert_eq!(f.amount(ata(&f.server.pubkey(), &f.mint)), 30);
    assert_eq!(f.amount(f.source), u64::MAX);
}

fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    spl_associated_token_account_client::address::get_associated_token_address_with_program_id(
        owner,
        mint,
        &spl_token::id(),
    )
}

fn create_ata(funder: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Instruction {
    spl_associated_token_account_client::instruction::create_associated_token_account_idempotent(
        funder,
        owner,
        mint,
        &spl_token::id(),
    )
}

fn invalid_argument(err: &FailedTransactionMetadata) {
    assert_eq!(
        err.err,
        TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::InvalidArgument
        )
    );
}

impl Fixture {
    fn refund(&self, amount: u64, h: u64, f: u64) -> Instruction {
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new_readonly(self.server.pubkey(), true),
                AccountMeta::new(self.payment, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(ata(&self.server.pubkey(), &self.mint), false),
                AccountMeta::new(self.source, false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data: refund_data(amount, h, f),
        }
    }

    fn check(&self, h: u64, f: u64, server_tokens: u64, payer_tokens: u64, surplus: u64) {
        let state = self.state();
        assert_eq!(state.held, h);
        assert_eq!(state.refundable, f);
        assert_eq!(state.payer, self.payer.pubkey());
        assert_eq!(state.server, self.server.pubkey());
        assert_eq!(state.mint, self.mint);
        assert_eq!(state.salt, self.salt);
        assert_eq!(state.maximum, M);
        assert_eq!(state.capture_deadline, DC);
        assert_eq!(state.refund_deadline, DR);
        assert!(h.checked_add(f).unwrap() <= M);
        assert_eq!(self.amount(self.vault), h + surplus);
        assert_eq!(self.amount(self.source), payer_tokens);
        assert_eq!(
            self.amount(ata(&self.server.pubkey(), &self.mint)),
            server_tokens
        );
    }
}
