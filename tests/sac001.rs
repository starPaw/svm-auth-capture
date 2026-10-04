//! All acceptance assertions execute the compiled SBF program in LiteSVM.
use litesvm::{
    types::{FailedTransactionMetadata, TransactionResult},
    LiteSVM,
};
use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::{AccountMeta, Instruction},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction, system_program,
    transaction::{Transaction, TransactionError},
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};
use svm_auth_capture::{authorize_data, payment_address, Payment, ID, PAYMENT_LEN, SEED};

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
        let mut svm = LiteSVM::new();
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

#[test]
fn authorize_exact_deposit_terms_and_separate_rent() {
    let mut f = Fixture::new();
    let sol_before = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
    f.authorized();
    assert_eq!(f.amount(f.vault), M);
    let payment_rent = f.svm.minimum_balance_for_rent_exemption(PAYMENT_LEN);
    let vault_rent = f.svm.minimum_balance_for_rent_exemption(TokenAccount::LEN);
    assert_eq!(f.svm.get_balance(&f.payment), Some(payment_rent));
    assert_eq!(f.svm.get_balance(&f.vault), Some(vault_rent));
    assert_eq!(
        sol_before - f.svm.get_balance(&f.sponsor.pubkey()).unwrap(),
        payment_rent + vault_rent + 10_000
    );
    println!("rent: payment={payment_rent} vault={vault_rent} lamports; tx fee=10000 lamports; hold=100 token base units");
}

#[test]
fn insufficient_authorize_rolls_back_initialization_and_rent() {
    let mut f = Fixture::new();
    let mut ix = f.authorize();
    ix.data = authorize_data(f.salt, 1_001, DC, DR);
    f.fails(&[ix], Some(0));
    assert!(f.svm.get_account(&f.payment).is_none());
    assert!(f.svm.get_account(&f.vault).is_none());
    assert_eq!(f.amount(f.source), 1_000);
}

#[test]
fn failed_token_cpi_after_authorize_rolls_back_entire_transaction() {
    let mut f = Fixture::new();
    let extra = spl_token::instruction::transfer_checked(
        &spl_token::id(),
        &f.source,
        &f.mint,
        &f.vault,
        &f.payer.pubkey(),
        &[],
        901,
        6,
    )
    .unwrap();
    let err = f.fails(&[f.authorize(), extra], Some(0));
    assert!(err
        .meta
        .logs
        .iter()
        .any(|line| line == &format!("Program {ID} success")));
    assert!(err
        .meta
        .logs
        .iter()
        .any(|line| line.starts_with(&format!("Program {} failed", spl_token::id()))));
    assert!(f.svm.get_account(&f.payment).is_none());
    assert!(f.svm.get_account(&f.vault).is_none());
}

#[test]
fn duplicate_conflicting_and_transaction_duplicate_authorizations_collect_once() {
    let mut f = Fixture::new();
    f.fails(&[f.authorize(), f.authorize()], Some(0));
    f.authorized();
    f.fails(&[f.authorize()], Some(0));
    for change in 0..5 {
        let mut ix = f.authorize();
        match change {
            0 => ix.accounts[1].pubkey = f.outsider.pubkey(),
            1 => ix.data[43..51].copy_from_slice(&101u64.to_le_bytes()),
            2 => ix.data[51..59].copy_from_slice(&(DC + 1).to_le_bytes()),
            3 => ix.data[59..67].copy_from_slice(&(DR + 1).to_le_bytes()),
            4 => ix.data[11] ^= 1,
            _ => unreachable!(),
        }
        f.fails(&[ix], Some(0));
    }
    f.time(DC);
    f.send(&[f.reclaim()], Some(0)).unwrap();
    // Time must be valid for authorize so rejection proves the persistent tombstone.
    f.time(NOW);
    f.fails(&[f.authorize()], Some(0));
    let mut conflicting = f.authorize();
    conflicting.data[43..51].copy_from_slice(&101u64.to_le_bytes());
    f.fails(&[conflicting], Some(0));
    assert_eq!(f.amount(f.source), 1_000);
    assert_eq!(f.state().held, 0);
}

#[test]
fn alternate_bump_is_rejected() {
    let mut f = Fixture::new();
    let canonical = payment_address(&ID, &f.payer.pubkey(), &f.salt).1;
    let alternate = (0..canonical)
        .rev()
        .find_map(|bump| {
            Pubkey::create_program_address(
                &[SEED, f.payer.pubkey().as_ref(), &f.salt, &[bump]],
                &ID,
            )
            .ok()
        })
        .unwrap();
    let mut ix = f.authorize();
    ix.accounts[2].pubkey = alternate;
    ix.accounts[5].pubkey = ata(&alternate, &f.mint);
    f.fails(&[ix], Some(0));
    assert!(f.svm.get_account(&alternate).is_none());
}

#[test]
fn foreign_malformed_and_initialized_payment_accounts_fail_closed() {
    for kind in 0..4 {
        let mut f = Fixture::new();
        let (owner, data) = match kind {
            0 => (f.outsider.pubkey(), vec![]),
            1 => (ID, vec![0; PAYMENT_LEN]),
            2 => (system_program::id(), vec![0; 1]),
            3 => (
                ID,
                Payment {
                    payer: f.payer.pubkey(),
                    server: f.server.pubkey(),
                    mint: f.mint,
                    salt: f.salt,
                    maximum: M,
                    capture_deadline: DC,
                    refund_deadline: DR,
                    held: 0,
                    refundable: 0,
                }
                .encode(),
            ),
            _ => unreachable!(),
        };
        f.svm
            .set_account(
                f.payment,
                Account {
                    lamports: 10_000_000,
                    data,
                    owner,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        f.fails(&[f.authorize()], Some(0));
    }
}

#[test]
fn wrong_programs_mints_atas_authorities_and_aliases_fail() {
    for kind in 0..13 {
        let mut f = Fixture::new();
        let mut ix = f.authorize();
        match kind {
            0 => ix.accounts[8].pubkey = spl_token_2022_id(),
            1 => ix.accounts[3].pubkey = f.outsider.pubkey(),
            2 => ix.accounts[4].pubkey = f.outsider.pubkey(),
            3 => ix.accounts[5].pubkey = f.source,
            4 => ix.accounts[1].pubkey = f.payer.pubkey(),
            5 => f.edit_token(f.source, |s| s.owner = Pubkey::new_unique()),
            6 => f.edit_token(f.source, |s| s.mint = Pubkey::new_unique()),
            7 => {
                let mut a = f.svm.get_account(&f.mint).unwrap();
                a.owner = spl_token_2022_id();
                f.svm.set_account(f.mint, a).unwrap();
            }
            8 => ix.accounts[7].pubkey = spl_token::id(),
            9 => ix.accounts[9].pubkey = spl_token::id(),
            10 => {
                let mut a = f.svm.get_account(&f.source).unwrap();
                a.owner = system_program::id();
                f.svm.set_account(f.source, a).unwrap();
            }
            11 => ix.accounts[3].pubkey = f.payment,
            12 => f.edit_token(f.source, |s| s.state = AccountState::Frozen),
            _ => unreachable!(),
        }
        f.fails(&[ix], Some(0));
    }
}

fn spl_token_2022_id() -> Pubkey {
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse()
        .unwrap()
}

#[test]
fn payer_and_creation_funder_signatures_are_required() {
    let mut f = Fixture::new();
    let mut ix = f.authorize();
    ix.accounts[0].is_signer = false;
    f.fails(&[ix], None);
    let mut ix = f.authorize();
    ix.accounts[6] = AccountMeta::new(f.outsider.pubkey(), false);
    f.fails(&[ix], Some(0));
    // A valid signature by another wallet cannot spend the stored payer's source.
    let mut ix = f.authorize();
    ix.accounts[0].pubkey = f.outsider.pubkey();
    f.fails(&[ix], Some(2));
    // Keep the payer account/message intact but supply a cryptographically wrong signature.
    let mut tx = Transaction::new_signed_with_payer(
        &[f.authorize()],
        Some(&f.sponsor.pubkey()),
        &[&f.sponsor, &f.payer],
        f.svm.latest_blockhash(),
    );
    let payer_slot = tx
        .message
        .account_keys
        .iter()
        .position(|key| key == &f.payer.pubkey())
        .unwrap();
    tx.signatures[payer_slot] = f.outsider.sign_message(&tx.message_data());
    let before = f.account_snapshot();
    let sol_before = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
    let err = f.svm.send_transaction(tx).unwrap_err();
    assert_eq!(err.err, TransactionError::SignatureFailure);
    assert_eq!(f.account_snapshot(), before);
    assert_eq!(f.svm.get_balance(&f.sponsor.pubkey()).unwrap(), sol_before);
}

#[test]
fn plain_pda_and_ata_lamport_prefunding_does_not_initialize_or_block() {
    for lamports in [1, 20_000_000] {
        let mut f = Fixture::new();
        let funding = [
            system_instruction::transfer(&f.sponsor.pubkey(), &f.payment, lamports),
            system_instruction::transfer(&f.sponsor.pubkey(), &f.vault, lamports),
        ];
        f.send(&funding, None).unwrap();
        let p = f.svm.get_account(&f.payment).unwrap();
        assert_eq!(p.owner, system_program::id());
        assert!(p.data.is_empty());
        let sol_before = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
        f.authorized();
        assert_eq!(f.amount(f.vault), M);
        let payment_rent = f.svm.minimum_balance_for_rent_exemption(PAYMENT_LEN);
        let vault_rent = f.svm.minimum_balance_for_rent_exemption(TokenAccount::LEN);
        assert_eq!(
            f.svm.get_balance(&f.payment),
            Some(lamports.max(payment_rent))
        );
        assert_eq!(f.svm.get_balance(&f.vault), Some(lamports.max(vault_rent)));
        assert_eq!(
            sol_before - f.svm.get_balance(&f.sponsor.pubkey()).unwrap(),
            payment_rent.saturating_sub(lamports) + vault_rent.saturating_sub(lamports) + 10_000
        );
    }
}

#[test]
fn unsolicited_vault_tokens_remain_surplus_through_reclaim() {
    let mut f = Fixture::new();
    f.send(
        &[create_ata(&f.sponsor.pubkey(), &f.payment, &f.mint)],
        None,
    )
    .unwrap();
    let transfer = spl_token::instruction::transfer_checked(
        &spl_token::id(),
        &f.source,
        &f.mint,
        &f.vault,
        &f.payer.pubkey(),
        &[],
        23,
        6,
    )
    .unwrap();
    f.send(&[transfer], Some(0)).unwrap();
    assert!(f.svm.get_account(&f.payment).is_none());
    f.send(&[f.authorize()], Some(0)).unwrap();
    let original = f.state();
    assert_eq!(original.held, M);
    assert_eq!(f.amount(f.source), 877);
    assert_eq!(f.amount(f.vault), 123);
    f.time(DC);
    f.send(&[f.reclaim()], Some(0)).unwrap();
    assert_eq!(f.amount(f.source), 977);
    assert_eq!(f.amount(f.vault), 23);
    let mut expected = original;
    expected.held = 0;
    assert_eq!(f.state(), expected);
    assert!(f.svm.get_account(&f.vault).is_some());
}

#[test]
fn invalid_existing_vault_cannot_be_accepted_as_a_hold() {
    for kind in 0..6 {
        let mut f = Fixture::new();
        f.send(
            &[create_ata(&f.sponsor.pubkey(), &f.payment, &f.mint)],
            None,
        )
        .unwrap();
        f.edit_token(f.vault, |s| match kind {
            0 => s.owner = Pubkey::new_unique(),
            1 => s.mint = Pubkey::new_unique(),
            2 => s.delegate = COption::Some(Pubkey::new_unique()),
            3 => s.close_authority = COption::Some(Pubkey::new_unique()),
            4 => s.state = AccountState::Frozen,
            5 => s.is_native = COption::Some(1),
            _ => unreachable!(),
        });
        f.fails(&[f.authorize()], Some(0));
        assert!(f.svm.get_account(&f.payment).is_none());
    }
}

#[test]
fn reclaim_fails_at_dc_minus_one_and_succeeds_at_exact_dc_on_separate_fixtures() {
    for timestamp in [DC - 1, DC] {
        let mut f = Fixture::new();
        f.authorized();
        f.time(timestamp);
        if timestamp < DC {
            f.fails(&[f.reclaim()], Some(0));
            assert_eq!(f.state().held, M);
            assert_eq!(f.amount(f.vault), M);
        } else {
            f.send(&[f.reclaim()], Some(0)).unwrap();
            assert_eq!(f.amount(f.source), 1_000);
            assert_eq!(f.amount(f.vault), 0);
            assert_eq!((f.state().held, f.state().refundable), (0, 0));
        }
    }
}

#[test]
fn reclaim_succeeds_at_dc_plus_one_with_server_absent() {
    let mut f = Fixture::new();
    f.authorized();
    f.time(DC + 1);
    assert!(f.svm.get_account(&f.server.pubkey()).is_none());
    // Rebuild the instruction from persistent fields, without an application journal.
    let state = f.state();
    let payment = payment_address(&ID, &state.payer, &state.salt).0;
    let mut ix = Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(state.payer, true),
            AccountMeta::new(payment, false),
            AccountMeta::new_readonly(state.mint, false),
            AccountMeta::new(ata(&payment, &state.mint), false),
            AccountMeta::new(ata(&state.payer, &state.mint), false),
            AccountMeta::new_readonly(spl_token::id(), false),
        ],
        data: vec![1],
    };
    // The payer can also submit/pay directly, with no sponsor instruction account.
    ix.accounts[0].is_writable = true;
    f.svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&f.payer.pubkey()),
        &[&f.payer],
        f.svm.latest_blockhash(),
    );
    let sol_before = f.svm.get_balance(&f.payer.pubkey()).unwrap();
    f.svm.send_transaction(tx).unwrap();
    assert_eq!(
        sol_before - f.svm.get_balance(&f.payer.pubkey()).unwrap(),
        5_000
    );
    assert_eq!(f.amount(f.source), 1_000);
    assert_eq!((f.state().held, f.state().refundable), (0, 0));
}

#[test]
fn server_sponsor_and_unrelated_signer_cannot_reclaim() {
    for (key, signer) in [(1, Some(1)), (2, Some(2)), (3, None)] {
        let mut f = Fixture::new();
        f.authorized();
        f.time(DC);
        let mut ix = f.reclaim();
        ix.accounts[0].pubkey = match key {
            1 => f.server.pubkey(),
            2 => f.outsider.pubkey(),
            _ => f.sponsor.pubkey(),
        };
        f.fails(&[ix], signer);
    }
    let mut f = Fixture::new();
    f.authorized();
    f.time(DC);
    let mut ix = f.reclaim();
    ix.accounts[0].is_signer = false;
    f.fails(&[ix], None);
}

#[test]
fn repeated_and_reordered_reclaim_transfers_only_once() {
    let mut f = Fixture::new();
    f.authorized();
    f.time(DC);
    f.fails(&[f.reclaim(), f.reclaim()], Some(0));
    assert_eq!(f.state().held, M);
    let mut bad = f.reclaim();
    bad.accounts[4].pubkey = f.vault;
    f.fails(&[bad.clone(), f.reclaim()], Some(0));
    f.fails(&[f.reclaim(), bad], Some(0));
    f.send(&[f.reclaim()], Some(0)).unwrap();
    f.fails(&[f.reclaim()], Some(0));
    assert_eq!(f.amount(f.source), 1_000);
    assert_eq!(f.amount(f.vault), 0);
}

#[test]
fn frozen_reassigned_wrong_mint_owner_or_destination_preserves_hold() {
    for kind in 0..5 {
        let mut f = Fixture::new();
        f.authorized();
        f.time(DC);
        let mut ix = f.reclaim();
        match kind {
            0 => {
                let freeze = spl_token::instruction::freeze_account(
                    &spl_token::id(),
                    &f.source,
                    &f.mint,
                    &f.payer.pubkey(),
                    &[],
                )
                .unwrap();
                f.send(&[freeze], Some(0)).unwrap();
            }
            1 => {
                let assign = spl_token::instruction::set_authority(
                    &spl_token::id(),
                    &f.source,
                    Some(&f.outsider.pubkey()),
                    spl_token::instruction::AuthorityType::AccountOwner,
                    &f.payer.pubkey(),
                    &[],
                )
                .unwrap();
                f.send(&[assign], Some(0)).unwrap();
            }
            2 => f.edit_token(f.source, |s| s.mint = Pubkey::new_unique()),
            3 => {
                let mut a = f.svm.get_account(&f.source).unwrap();
                a.owner = system_program::id();
                f.svm.set_account(f.source, a).unwrap();
            }
            4 => ix.accounts[4].pubkey = f.vault,
            _ => unreachable!(),
        }
        f.fails(&[ix], Some(0));
        assert_eq!(f.state().held, M);
        assert_eq!(f.amount(f.vault), M);
    }
}

#[test]
fn missing_payer_ata_requires_atomic_repair_without_redirect() {
    let mut f = Fixture::new();
    f.authorized();
    // Move the payer's unrelated balance away, then close its ATA using real Token instructions.
    let other = ata(&f.outsider.pubkey(), &f.mint);
    let setup = [
        create_ata(&f.sponsor.pubkey(), &f.outsider.pubkey(), &f.mint),
        spl_token::instruction::transfer_checked(
            &spl_token::id(),
            &f.source,
            &f.mint,
            &other,
            &f.payer.pubkey(),
            &[],
            900,
            6,
        )
        .unwrap(),
        spl_token::instruction::close_account(
            &spl_token::id(),
            &f.source,
            &f.payer.pubkey(),
            &f.payer.pubkey(),
            &[],
        )
        .unwrap(),
    ];
    f.send(&setup, Some(0)).unwrap();
    f.time(DC);
    f.fails(&[f.reclaim()], Some(0));
    // LiteSVM retains a zero-lamport System placeholder after Token CloseAccount.
    let closed = f.svm.get_account(&f.source).unwrap();
    assert_eq!(closed.owner, system_program::id());
    assert_eq!(closed.lamports, 0);
    assert!(closed.data.is_empty());
    let repair = create_ata(&f.sponsor.pubkey(), &f.payer.pubkey(), &f.mint);
    // A later failure rolls even the explicit ATA repair back.
    let mut bad = f.reclaim();
    bad.accounts[4].pubkey = f.vault;
    f.fails(&[repair.clone(), bad], Some(0));
    f.send(&[repair, f.reclaim()], Some(0)).unwrap();
    assert_eq!(f.amount(f.source), M);
    assert_eq!(f.amount(other), 900);
    assert_eq!(f.state().held, 0);
}

#[test]
fn repaired_frozen_destination_can_retry_without_consuming_hold() {
    let mut f = Fixture::new();
    f.authorized();
    f.time(DC);
    let freeze = spl_token::instruction::freeze_account(
        &spl_token::id(),
        &f.source,
        &f.mint,
        &f.payer.pubkey(),
        &[],
    )
    .unwrap();
    f.send(&[freeze], Some(0)).unwrap();
    f.fails(&[f.reclaim()], Some(0));
    let thaw = spl_token::instruction::thaw_account(
        &spl_token::id(),
        &f.source,
        &f.mint,
        &f.payer.pubkey(),
        &[],
    )
    .unwrap();
    f.send(&[thaw, f.reclaim()], Some(0)).unwrap();
    assert_eq!(f.amount(f.source), 1_000);
    assert_eq!(f.state().held, 0);
}

#[test]
fn persistent_terms_rent_and_vault_survive_and_no_close_reset_opcode_exists() {
    let mut f = Fixture::new();
    f.authorized();
    let original = f.state();
    let rent_before = (f.svm.get_balance(&f.payment), f.svm.get_balance(&f.vault));
    f.time(DC);
    f.send(&[f.reclaim()], Some(0)).unwrap();
    let mut expected = original;
    expected.held = 0;
    assert_eq!(f.state(), expected);
    for opcode in 2..=255 {
        let mut ix = f.reclaim();
        ix.data = vec![opcode];
        f.fails(&[ix], Some(0));
    }
    let mut ix = f.reclaim();
    ix.data = vec![1, 0];
    f.fails(&[ix], Some(0));
    assert_eq!(
        (f.svm.get_balance(&f.payment), f.svm.get_balance(&f.vault)),
        rent_before
    );
}

#[test]
fn invalid_deadline_profile_asset_amount_and_encoding_fail_atomically() {
    for kind in 0..11 {
        let mut f = Fixture::new();
        let mut ix = f.authorize();
        match kind {
            0 => ix.data = authorize_data(f.salt, 0, DC, DR),
            1 => ix.data = authorize_data(f.salt, M, NOW, DR),
            2 => ix.data = authorize_data(f.salt, M, 0, DR),
            3 => ix.data = authorize_data(f.salt, M, DC, DC - 1),
            4 => ix.data = authorize_data(f.salt, M, -1, DR),
            5 => ix.data = authorize_data(f.salt, M, DC, i64::MIN),
            6 => ix.data[1] = 2,
            7 => ix.data[2] = 1,
            8 => ix.data[3] = 1,
            9 => ix.accounts[3].pubkey = spl_token::native_mint::id(),
            10 => {
                ix.data.pop();
            }
            _ => unreachable!(),
        }
        f.fails(&[ix], Some(0));
    }
    let mut f = Fixture::new();
    let mut ix = f.authorize();
    ix.data.push(0);
    f.fails(&[ix], Some(0));
}

#[test]
fn integer_boundaries_are_checked_without_narrowing_or_overflow() {
    let mut f = Fixture::new();
    let mut ix = f.authorize();
    ix.data = authorize_data(f.salt, u64::MAX, DC, DR);
    f.fails(std::slice::from_ref(&ix), Some(0));
    // Reach vault addition overflow with otherwise sufficient source units.
    f.edit_token(f.source, |s| s.amount = u64::MAX);
    f.send(
        &[create_ata(&f.sponsor.pubkey(), &f.payment, &f.mint)],
        None,
    )
    .unwrap();
    f.edit_token(f.vault, |s| s.amount = 1);
    f.fails(&[ix], Some(0));
    assert!(f.svm.get_account(&f.payment).is_none());

    // The accepted contract allows representable maxima; do not invent a smaller ceiling.
    let mut f = Fixture::new();
    f.edit_token(f.source, |s| s.amount = u64::MAX);
    let mut asset = f.svm.get_account(&f.mint).unwrap();
    let mut mint = Mint::unpack(&asset.data).unwrap();
    mint.supply = u64::MAX;
    Mint::pack(mint, &mut asset.data).unwrap();
    f.svm.set_account(f.mint, asset).unwrap();
    let mut ix = f.authorize();
    ix.data = authorize_data(f.salt, u64::MAX, i64::MAX - 1, i64::MAX);
    f.send(&[ix], Some(0)).unwrap();
    assert_eq!(f.state().held, u64::MAX);
    assert_eq!(f.amount(f.source), 0);
    assert_eq!(f.amount(f.vault), u64::MAX);
    f.time(i64::MAX - 1);
    f.send(&[f.reclaim()], Some(0)).unwrap();
    assert_eq!(f.amount(f.source), u64::MAX);
    assert_eq!(f.state().held, 0);

    // Reclaim overflow is unreachable in a conserved mint, but rejects corrupt fixtures safely.
    let mut f = Fixture::new();
    f.authorized();
    f.time(DC);
    f.edit_token(f.source, |s| s.amount = u64::MAX);
    f.fails(&[f.reclaim()], Some(0));
}

#[test]
fn reclaim_revalidates_payment_identity_mint_program_and_vault() {
    for kind in 0..10 {
        let mut f = Fixture::new();
        f.authorized();
        f.time(DC);
        let mut ix = f.reclaim();
        match kind {
            0 => {
                let mut a = f.svm.get_account(&f.payment).unwrap();
                a.owner = system_program::id();
                f.svm.set_account(f.payment, a).unwrap();
            }
            1 => {
                let mut a = f.svm.get_account(&f.payment).unwrap();
                a.data[0] ^= 1;
                f.svm.set_account(f.payment, a).unwrap();
            }
            2 => {
                let mut a = f.svm.get_account(&f.payment).unwrap();
                a.data[104] ^= 1;
                f.svm.set_account(f.payment, a).unwrap();
            }
            3 => ix.accounts[2].pubkey = f.outsider.pubkey(),
            4 => ix.accounts[5].pubkey = spl_token_2022_id(),
            5 => f.edit_token(f.vault, |s| s.owner = Pubkey::new_unique()),
            6 => f.edit_token(f.vault, |s| {
                s.delegate = COption::Some(Pubkey::new_unique())
            }),
            7 => f.edit_token(f.vault, |s| {
                s.close_authority = COption::Some(Pubkey::new_unique())
            }),
            8 => f.edit_token(f.vault, |s| s.state = AccountState::Frozen),
            9 => f.edit_token(f.vault, |s| s.amount = M - 1),
            _ => unreachable!(),
        }
        f.fails(&[ix], Some(0));
    }
}

#[test]
fn equal_deadlines_including_i64_max_authorize_and_reclaim() {
    for dc in [DC, i64::MAX] {
        let mut f = Fixture::new();
        let mut ix = f.authorize();
        ix.data = authorize_data(f.salt, M, dc, dc);
        f.send(&[ix], Some(0)).unwrap();
        let original = f.state(); // Also exercises Payment::decode with Dr == Dc.
        assert_eq!(
            (original.capture_deadline, original.refund_deadline),
            (dc, dc)
        );
        assert_eq!((original.held, original.refundable), (M, 0));
        assert_eq!(f.amount(f.source), 1_000 - M);
        assert_eq!(f.amount(f.vault), M);
        f.time(dc);
        f.send(&[f.reclaim()], Some(0)).unwrap();
        let mut expected = original;
        expected.held = 0;
        assert_eq!(f.state(), expected);
        assert_eq!(f.amount(f.source), 1_000);
        assert_eq!(f.amount(f.vault), 0);
        f.time(NOW);
        f.fails(&[f.authorize()], Some(0));
    }
}

#[test]
fn authorize_succeeds_at_dc_minus_one_and_rejects_at_dc_and_dc_plus_one() {
    for timestamp in [DC - 1, DC, DC + 1] {
        let mut f = Fixture::new();
        f.time(timestamp);
        if timestamp < DC {
            f.authorized();
            assert_eq!(f.amount(f.vault), M);
        } else {
            f.fails(&[f.authorize()], Some(0));
            assert!(f.svm.get_account(&f.payment).is_none());
            assert!(f.svm.get_account(&f.vault).is_none());
        }
    }
}

#[test]
fn authorize_prepared_and_signed_before_dc_rejects_when_executed_at_dc() {
    let mut f = Fixture::new();
    f.time(DC - 1);
    let tx = Transaction::new_signed_with_payer(
        &[f.authorize()],
        Some(&f.sponsor.pubkey()),
        &[&f.sponsor, &f.payer],
        f.svm.latest_blockhash(),
    );
    let before = f.account_snapshot();
    let sol_before = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
    f.time(DC);
    // Submit the same signed transaction; neither message nor blockhash is refreshed.
    let err = f.svm.send_transaction(tx).unwrap_err();
    assert_eq!(
        err.err,
        TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::InvalidArgument
        )
    );
    assert!(err
        .meta
        .logs
        .iter()
        .any(|line| line.contains(&format!("Program {ID} invoke"))));
    assert_eq!(f.account_snapshot(), before);
    assert_eq!(
        sol_before - f.svm.get_balance(&f.sponsor.pubkey()).unwrap(),
        10_000
    );
}

#[test]
fn nonpositive_execution_time_does_not_restrict_valid_positive_deadlines() {
    for timestamp in [-1, 0] {
        let mut f = Fixture::new();
        f.time(timestamp);
        f.authorized();
        f.time(DC);
        f.send(&[f.reclaim()], Some(0)).unwrap();
        assert_eq!(f.state().held, 0);
        assert_eq!(f.amount(f.source), 1_000);
    }
}

#[test]
fn payer_can_be_its_own_fee_and_creation_sponsor() {
    let mut f = Fixture::new();
    let mut ix = f.authorize();
    ix.accounts[6] = AccountMeta::new(f.payer.pubkey(), true);
    let sol_before = f.svm.get_balance(&f.payer.pubkey()).unwrap();
    let sponsor_before = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&f.payer.pubkey()),
        &[&f.payer],
        f.svm.latest_blockhash(),
    );
    f.svm.send_transaction(tx).unwrap();
    assert_eq!(f.state().held, M);
    assert_eq!(f.amount(f.source), 1_000 - M);
    assert_eq!(f.amount(f.vault), M);
    let rent = f.svm.minimum_balance_for_rent_exemption(PAYMENT_LEN)
        + f.svm.minimum_balance_for_rent_exemption(TokenAccount::LEN);
    assert_eq!(
        sol_before - f.svm.get_balance(&f.payer.pubkey()).unwrap(),
        rent + 5_000
    );
    assert_eq!(
        f.svm.get_balance(&f.sponsor.pubkey()).unwrap(),
        sponsor_before
    );
}

#[test]
fn pending_authorizations_and_reclaims_transfer_once_in_either_order() {
    // LiteSVM executes serially. Prepare both signed contenders before execution,
    // then cover both orders of the runtime's writable-account serialization.
    for reverse in [false, true] {
        let mut f = Fixture::new();
        let first = f.authorize();
        let mut second = first.clone();
        second.accounts[6] = AccountMeta::new(f.payer.pubkey(), true);
        let mut transactions: Vec<_> = [first, second]
            .into_iter()
            .map(|ix| {
                Transaction::new_signed_with_payer(
                    &[ix],
                    Some(&f.sponsor.pubkey()),
                    &[&f.sponsor, &f.payer],
                    f.svm.latest_blockhash(),
                )
            })
            .collect();
        if reverse {
            transactions.reverse();
        }
        f.svm.send_transaction(transactions.remove(0)).unwrap();
        let before = f.account_snapshot();
        let sol_before = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
        let err = f.svm.send_transaction(transactions.remove(0)).unwrap_err();
        assert_eq!(
            err.err,
            TransactionError::InstructionError(
                0,
                solana_sdk::instruction::InstructionError::AccountAlreadyInitialized
            )
        );
        assert_eq!(f.account_snapshot(), before);
        assert_eq!(
            sol_before - f.svm.get_balance(&f.sponsor.pubkey()).unwrap(),
            10_000
        );
        assert_eq!(f.amount(f.vault), M);
        assert_eq!(f.state().held, M);

        f.time(DC);
        f.svm.expire_blockhash();
        let first = f.reclaim();
        let mut second = first.clone();
        second.accounts[0].is_writable = true;
        let mut transactions: Vec<_> = [first, second]
            .into_iter()
            .map(|ix| {
                Transaction::new_signed_with_payer(
                    &[ix],
                    Some(&f.sponsor.pubkey()),
                    &[&f.sponsor, &f.payer],
                    f.svm.latest_blockhash(),
                )
            })
            .collect();
        if reverse {
            transactions.reverse();
        }
        f.svm.send_transaction(transactions.remove(0)).unwrap();
        let before = f.account_snapshot();
        let sol_before = f.svm.get_balance(&f.sponsor.pubkey()).unwrap();
        let err = f.svm.send_transaction(transactions.remove(0)).unwrap_err();
        assert_eq!(
            err.err,
            TransactionError::InstructionError(
                0,
                solana_sdk::instruction::InstructionError::InvalidArgument
            )
        );
        assert_eq!(f.account_snapshot(), before);
        assert_eq!(
            sol_before - f.svm.get_balance(&f.sponsor.pubkey()).unwrap(),
            10_000
        );
        assert_eq!(f.amount(f.source), 1_000);
        assert_eq!(f.amount(f.vault), 0);
        assert_eq!((f.state().held, f.state().refundable), (0, 0));
    }
}
