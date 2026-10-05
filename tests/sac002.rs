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
    authorize_data, capture_data, payment_address, void_data, Payment, ID, PAYMENT_LEN,
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

#[test]
fn partial_repeated_and_ordinary_full_capture_pay_exactly() {
    let mut f = Fixture::funded();
    f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
    f.balances(70, 30, 30, 0, 0);
    f.send(&[f.capture(20, false, 70, 30)], Some(1)).unwrap();
    f.balances(50, 50, 50, 0, 0);
    f.send(&[f.capture(50, false, 50, 50)], Some(1)).unwrap();
    f.balances(0, 100, 100, 0, 0);
}

#[test]
fn zero_and_over_capture_fail_before_and_after_partial_capture() {
    for release in [false, true] {
        let mut f = Fixture::funded();
        for amount in [0, 101, u64::MAX] {
            invalid_argument(&f.fails(&[f.capture(amount, release, 100, 0)], Some(1)));
        }
        f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
        for amount in [0, 71, 100] {
            invalid_argument(&f.fails(&[f.capture(amount, release, 70, 30)], Some(1)));
        }
        f.balances(70, 30, 30, 0, 0);
    }
}

#[test]
fn each_server_operation_independently_requires_both_expected_fields() {
    for op in 0..3 {
        let mut f = Fixture::funded();
        f.send(&[f.capture(50, false, 100, 0)], Some(1)).unwrap();
        for (h, captured) in [(49, 50), (50, 49)] {
            let ix = match op {
                0 => f.capture(10, false, h, captured),
                1 => f.capture(10, true, h, captured),
                _ => f.void(h, captured),
            };
            invalid_argument(&f.fails(&[ix], Some(1)));
        }
        f.balances(50, 50, 50, 0, 0);
    }
}

#[test]
fn consumed_consent_replayed_with_fresh_signed_bytes_cannot_transfer_again() {
    for op in 0..3 {
        let mut f = Fixture::funded();
        let ix = match op {
            0 => f.capture(30, false, 100, 0),
            1 => f.capture(30, true, 100, 0),
            _ => f.void(100, 0),
        };
        f.send(std::slice::from_ref(&ix), Some(1)).unwrap();
        invalid_argument(&f.fails(&[ix], Some(1)));
        match op {
            0 => f.balances(70, 30, 30, 0, 0),
            1 => f.balances(0, 30, 30, 70, 0),
            _ => f.balances(0, 0, 0, 100, 0),
        }
    }
}

#[test]
fn server_native_signature_cannot_be_replaced_by_payer_sponsor_or_facilitator() {
    for op in 0..3 {
        let mut f = Fixture::funded();
        let base = match op {
            0 => f.capture(30, false, 100, 0),
            1 => f.capture(30, true, 100, 0),
            _ => f.void(100, 0),
        };
        let mut missing = base.clone();
        missing.accounts[0].is_signer = false;
        let err = f.fails(&[missing], None);
        assert_eq!(
            err.err,
            TransactionError::InstructionError(
                0,
                solana_sdk::instruction::InstructionError::MissingRequiredSignature
            )
        );
        for role in [0, 1, 2] {
            let mut wrong = base.clone();
            let (key, signer) = match role {
                0 => (f.payer.pubkey(), Some(0)),
                1 => (f.sponsor.pubkey(), None),
                _ => (f.outsider.pubkey(), Some(2)),
            };
            wrong.accounts[0] = AccountMeta::new_readonly(key, true);
            invalid_argument(&f.fails(&[wrong], signer));
        }
        // Declared required server signature is absent at the cryptographic boundary.
        let mut tx = Transaction::new_with_payer(&[base], Some(&f.sponsor.pubkey()));
        tx.partial_sign(&[&f.sponsor], f.svm.latest_blockhash());
        let before = f.account_snapshot();
        let sol = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
        let err = f.svm.send_transaction(tx).unwrap_err();
        assert_eq!(err.err, TransactionError::SignatureFailure);
        assert_eq!(f.account_snapshot(), before);
        assert_eq!(f.svm.get_balance(&f.sponsor.pubkey()).unwrap(), sol);
    }
}

#[test]
fn changing_signed_amount_or_release_flag_invalidates_server_consent() {
    for release in [false, true] {
        for byte in [1, 9] {
            let mut f = Fixture::funded();
            let ix = f.capture(30, release, 100, 0);
            let mut tx = f.prepare(&ix, true);
            tx.message.instructions[0].data[byte] ^= 1;
            // A relay can refresh its own sponsor signature, not the server's consent.
            tx.signatures[0] = f.sponsor.sign_message(&tx.message_data());
            let before = f.account_snapshot();
            let sol = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
            let err = f.svm.send_transaction(tx).unwrap_err();
            assert_eq!(err.err, TransactionError::SignatureFailure);
            assert_eq!(f.account_snapshot(), before);
            assert_eq!(f.svm.get_balance(&f.sponsor.pubkey()).unwrap(), sol);
        }
    }
}

#[test]
fn substituted_or_reassigned_server_destination_is_rejected() {
    for release in [false, true] {
        let mut f = Fixture::funded();
        f.send(
            &[create_ata(
                &f.sponsor.pubkey(),
                &f.outsider.pubkey(),
                &f.mint,
            )],
            None,
        )
        .unwrap();
        let mut ix = f.capture(30, release, 100, 0);
        ix.accounts[4].pubkey = ata(&f.outsider.pubkey(), &f.mint);
        f.fails(&[ix], Some(1));
        let receiver = ata(&f.server.pubkey(), &f.mint);
        let set_authority = spl_token::instruction::set_authority(
            &spl_token::id(),
            &receiver,
            Some(&f.outsider.pubkey()),
            spl_token::instruction::AuthorityType::AccountOwner,
            &f.server.pubkey(),
            &[],
        )
        .unwrap();
        f.send(&[set_authority], Some(1)).unwrap();
        f.fails(&[f.capture(30, release, 100, 0)], Some(1));
        f.balances(100, 0, 0, 0, 0);
    }
}

#[test]
fn prepared_duplicate_conflicting_capture_and_void_contenders_serialize_in_both_orders() {
    for competing in 0..3 {
        for reverse in [false, true] {
            let mut f = Fixture::funded();
            let first = f.capture(30, false, 100, 0);
            let mut second = match competing {
                0 => first.clone(),
                1 => f.capture(20, false, 100, 0),
                _ => f.void(100, 0),
            };
            // Distinct signed transaction bytes for an identical economic consent.
            second.accounts[0].is_writable = true;
            f.svm.expire_blockhash();
            let mut txs: Vec<_> = [first, second]
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
            let paid = if reverse {
                match competing {
                    0 => 30,
                    1 => 20,
                    _ => 0,
                }
            } else {
                30
            };
            if paid == 0 {
                f.balances(0, 0, 0, 100, 0);
            } else {
                f.balances(100 - paid, paid, paid, 0, 0);
                // A new server-signed consent against the actual winning pair is required.
                f.send(&[f.void(100 - paid, paid)], Some(1)).unwrap();
                f.balances(0, paid, paid, 100 - paid, 0);
            }
        }
    }
}

#[test]
fn capture_and_atomic_capture_void_obey_execution_deadline() {
    for release in [false, true] {
        for time in [DC - 1, DC, DC + 1] {
            let mut f = Fixture::funded();
            f.time(time);
            let ix = f.capture(30, release, 100, 0);
            if time < DC {
                f.send(&[ix], Some(1)).unwrap();
                f.balances(
                    if release { 0 } else { 70 },
                    30,
                    30,
                    if release { 70 } else { 0 },
                    0,
                );
            } else {
                invalid_argument(&f.fails(&[ix], Some(1)));
                f.balances(100, 0, 0, 0, 0);
            }
        }
        let mut f = Fixture::funded();
        f.time(DC - 1);
        let ix = f.capture(30, release, 100, 0);
        let tx = f.prepare(&ix, true);
        let before = f.account_snapshot();
        let sol = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
        f.time(DC);
        invalid_argument(&f.svm.send_transaction(tx).unwrap_err());
        assert_eq!(f.account_snapshot(), before);
        assert_eq!(
            sol - f.svm.get_balance(&f.sponsor.pubkey()).unwrap(),
            10_000
        );
    }
}

#[test]
fn void_has_no_deadline_and_preserves_previously_captured_value() {
    for time in [DC - 1, DC, DC + 1, DR, i64::MAX] {
        let mut f = Fixture::funded();
        f.send(&[f.capture(50, false, 100, 0)], Some(1)).unwrap();
        f.time(time);
        f.send(&[f.void(50, 50)], Some(1)).unwrap();
        f.balances(0, 50, 50, 50, 0);
    }
}

#[test]
fn prepared_capture_reclaim_contenders_obey_partition_in_both_orders() {
    for reclaim_first in [false, true] {
        let mut f = Fixture::funded();
        f.time(DC - 1);
        f.svm.expire_blockhash();
        let capture = Transaction::new_signed_with_payer(
            &[f.capture(30, false, 100, 0)],
            Some(&f.sponsor.pubkey()),
            &[&f.sponsor, &f.server],
            f.svm.latest_blockhash(),
        );
        let reclaim = Transaction::new_signed_with_payer(
            &[f.reclaim()],
            Some(&f.sponsor.pubkey()),
            &[&f.sponsor, &f.payer],
            f.svm.latest_blockhash(),
        );
        if reclaim_first {
            f.time(DC);
            f.svm.send_transaction(reclaim).unwrap();
            let before = f.account_snapshot();
            invalid_argument(&f.svm.send_transaction(capture).unwrap_err());
            assert_eq!(f.account_snapshot(), before);
            f.balances(0, 0, 0, 100, 0);
        } else {
            f.svm.send_transaction(capture).unwrap();
            f.balances(70, 30, 30, 0, 0);
            f.time(DC);
            f.svm.send_transaction(reclaim).unwrap();
            f.balances(0, 30, 30, 70, 0);
        }
    }
    // Explicitly demonstrate both sides of the boundary with fresh fixtures.
    for time in [DC - 1, DC, DC + 1] {
        let mut f = Fixture::funded();
        f.time(time);
        if time < DC {
            f.fails(&[f.reclaim()], Some(0));
            f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
        } else {
            f.fails(&[f.capture(30, false, 100, 0)], Some(1));
            f.send(&[f.reclaim()], Some(0)).unwrap();
        }
    }
}

#[test]
fn atomic_partial_capture_void_and_full_capture_skip_zero_return() {
    for amount in [30, 100] {
        let mut f = Fixture::funded();
        if amount == 100 {
            f.freeze(f.source, true);
        }
        let meta = f.send(&[f.capture(amount, true, 100, 0)], Some(1)).unwrap();
        let transfer_count = meta
            .logs
            .iter()
            .filter(|line| line.contains("Instruction: TransferChecked"))
            .count();
        assert_eq!(transfer_count, if amount == 100 { 1 } else { 2 });
        f.balances(0, amount, amount, 100 - amount, 0);
    }
}

#[test]
fn atomic_server_and_payer_cpi_failures_roll_back_and_repair_retry_same_pair() {
    for payer_leg in [false, true] {
        let mut f = Fixture::funded();
        let frozen = if payer_leg {
            f.source
        } else {
            ata(&f.server.pubkey(), &f.mint)
        };
        f.freeze(frozen, true);
        let ix = f.capture(30, true, 100, 0);
        let err = f.fails(std::slice::from_ref(&ix), Some(1));
        let transfers = err
            .meta
            .logs
            .iter()
            .filter(|s| s.contains("Instruction: TransferChecked"))
            .count();
        assert_eq!(transfers, if payer_leg { 2 } else { 1 });
        let token_success = format!("Program {} success", spl_token::id());
        assert_eq!(
            err.meta
                .logs
                .iter()
                .filter(|s| *s == &token_success)
                .count(),
            usize::from(payer_leg)
        );
        f.balances(100, 0, 0, 0, 0);
        f.freeze(frozen, false);
        f.time(DC - 1);
        f.send(&[ix], Some(1)).unwrap();
        f.balances(0, 30, 30, 70, 0);
    }
}

#[test]
fn standalone_capture_and_void_failed_transfers_preserve_pair_for_retry() {
    for capture in [false, true] {
        let mut f = Fixture::funded();
        let frozen = if capture {
            ata(&f.server.pubkey(), &f.mint)
        } else {
            f.source
        };
        let ix = if capture {
            f.capture(30, false, 100, 0)
        } else {
            f.void(100, 0)
        };
        f.freeze(frozen, true);
        let err = f.fails(std::slice::from_ref(&ix), Some(1));
        assert!(err
            .meta
            .logs
            .iter()
            .any(|s| s.contains("Instruction: TransferChecked")));
        f.balances(100, 0, 0, 0, 0);
        f.freeze(frozen, false);
        f.send(&[ix], Some(1)).unwrap();
        if capture {
            f.balances(70, 30, 30, 0, 0)
        } else {
            f.balances(0, 0, 0, 100, 0)
        };
    }
}

#[test]
fn partial_hold_reclaim_remains_payer_only_and_returns_residual_at_and_after_dc() {
    for time in [DC, DC + 1] {
        let mut f = Fixture::funded();
        f.send(&[f.capture(30, false, 100, 0)], Some(1)).unwrap();
        f.send(&[f.capture(20, false, 70, 30)], Some(1)).unwrap();
        f.time(time);
        let mut wrong = f.reclaim();
        wrong.accounts[0] = AccountMeta::new_readonly(f.server.pubkey(), true);
        f.fails(&[wrong], Some(1));
        f.send(&[f.reclaim()], Some(0)).unwrap();
        f.balances(0, 50, 50, 50, 0);
    }
}

#[test]
fn terminal_holds_reject_all_server_operations_and_reauthorization_keep_identity_and_surplus() {
    for terminal in 0..4 {
        let mut f = Fixture::funded();
        let payment_lamports = f.svm.get_balance(&f.payment).unwrap();
        let vault_lamports = f.svm.get_balance(&f.vault).unwrap();
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
        // Donation is outside accounting; replenish the fixture source to keep exact payout assertions.
        let top_up = spl_token::instruction::mint_to(
            &spl_token::id(),
            &f.mint,
            &f.source,
            &f.payer.pubkey(),
            &[],
            9,
        )
        .unwrap();
        f.send(&[top_up], Some(0)).unwrap();
        let (captured, returned) = match terminal {
            0 => {
                f.send(&[f.capture(100, false, 100, 0)], Some(1)).unwrap();
                (100, 0)
            }
            1 => {
                f.send(&[f.capture(30, true, 100, 0)], Some(1)).unwrap();
                (30, 70)
            }
            2 => {
                f.send(&[f.capture(50, false, 100, 0)], Some(1)).unwrap();
                f.send(&[f.void(50, 50)], Some(1)).unwrap();
                (50, 50)
            }
            _ => {
                f.send(&[f.capture(50, false, 100, 0)], Some(1)).unwrap();
                f.time(DC);
                f.send(&[f.reclaim()], Some(0)).unwrap();
                (50, 50)
            }
        };
        for ix in [
            f.capture(1, false, 0, captured),
            f.capture(1, true, 0, captured),
            f.void(0, captured),
        ] {
            invalid_argument(&f.fails(&[ix], Some(1)));
        }
        f.fails(&[f.authorize()], Some(0));
        f.balances(0, captured, captured, returned, 9);
        assert_eq!(f.svm.get_balance(&f.payment).unwrap(), payment_lamports);
        assert_eq!(f.svm.get_balance(&f.vault).unwrap(), vault_lamports);
    }
}

#[test]
fn malformed_server_wire_and_new_payout_overflow_or_underbacking_fail_closed() {
    let mut f = Fixture::funded();
    for op in 0..3 {
        let base = match op {
            0 => f.capture(30, false, 100, 0),
            1 => f.capture(30, true, 100, 0),
            _ => f.void(100, 0),
        };
        let mut short = base.clone();
        short.data.pop();
        f.fails(&[short], Some(1));
        let mut extra = base.clone();
        extra.data.push(0);
        f.fails(&[extra], Some(1));
    }
    let mut invalid_bool = f.capture(30, false, 100, 0);
    invalid_bool.data[9] = 2;
    f.fails(&[invalid_bool], Some(1));
    let receiver = ata(&f.server.pubkey(), &f.mint);
    f.edit_token(receiver, |s| s.amount = u64::MAX);
    f.fails(&[f.capture(1, false, 100, 0)], Some(1));
    f.edit_token(receiver, |s| s.amount = 0);
    f.edit_token(f.vault, |s| s.amount = 99);
    f.fails(&[f.capture(1, false, 100, 0)], Some(1));
    f.fails(&[f.void(100, 0)], Some(1));
}
