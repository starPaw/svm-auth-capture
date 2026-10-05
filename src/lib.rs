//! SAC-001: persistent classic-SPL escrow authorization and direct payer reclaim.
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction, system_program,
    sysvar::Sysvar,
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};

// Local harness identity only; no supported network or deployment is declared.
pub const ID: Pubkey = Pubkey::new_from_array([42; 32]);
pub const SEED: &[u8] = b"auth-capture-v1";
pub const DISCRIMINATOR: &[u8; 8] = b"SACPAY01";
pub const PAYMENT_LEN: usize = 176;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    pub payer: Pubkey,
    pub server: Pubkey,
    pub mint: Pubkey,
    pub salt: [u8; 32],
    pub maximum: u64,
    pub capture_deadline: i64,
    pub refund_deadline: i64,
    pub held: u64,
    pub refundable: u64,
}

impl Payment {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAYMENT_LEN);
        out.extend_from_slice(DISCRIMINATOR);
        for key in [self.payer, self.server, self.mint] {
            out.extend_from_slice(key.as_ref());
        }
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.maximum.to_le_bytes());
        out.extend_from_slice(&self.capture_deadline.to_le_bytes());
        out.extend_from_slice(&self.refund_deadline.to_le_bytes());
        out.extend_from_slice(&self.held.to_le_bytes());
        out.extend_from_slice(&self.refundable.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != PAYMENT_LEN || &data[..8] != DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        let p = Self {
            payer: Pubkey::new_from_array(data[8..40].try_into().unwrap()),
            server: Pubkey::new_from_array(data[40..72].try_into().unwrap()),
            mint: Pubkey::new_from_array(data[72..104].try_into().unwrap()),
            salt: data[104..136].try_into().unwrap(),
            maximum: u64::from_le_bytes(data[136..144].try_into().unwrap()),
            capture_deadline: i64::from_le_bytes(data[144..152].try_into().unwrap()),
            refund_deadline: i64::from_le_bytes(data[152..160].try_into().unwrap()),
            held: u64::from_le_bytes(data[160..168].try_into().unwrap()),
            refundable: u64::from_le_bytes(data[168..176].try_into().unwrap()),
        };
        if p.payer == p.server
            || p.maximum == 0
            || p.capture_deadline <= 0
            || p.refund_deadline < p.capture_deadline
            || p.held
                .checked_add(p.refundable)
                .is_none_or(|sum| sum > p.maximum)
        {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(p)
    }
}

pub fn payment_address(program: &Pubkey, payer: &Pubkey, salt: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED, payer.as_ref(), salt], program)
}

/// Wire: authorize=0, version=1, escrow=0, fee=0:u64, salt:32, M:u64, Dc:i64, Dr:i64.
/// Accounts: payer(s,w), server, payment(w), mint, payer ATA(w), vault(w),
/// rent funder(s,w), System, classic Token, ATA program.
pub fn authorize_data(salt: [u8; 32], maximum: u64, dc: i64, dr: i64) -> Vec<u8> {
    let mut data = vec![0, 1, 0];
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&salt);
    data.extend_from_slice(&maximum.to_le_bytes());
    data.extend_from_slice(&dc.to_le_bytes());
    data.extend_from_slice(&dr.to_le_bytes());
    data
}

fn require(ok: bool, error: ProgramError) -> ProgramResult {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}

fn signer(account: &AccountInfo) -> ProgramResult {
    require(account.is_signer, ProgramError::MissingRequiredSignature)
}

fn writable(account: &AccountInfo) -> ProgramResult {
    require(account.is_writable, ProgramError::InvalidAccountData)
}

fn distinct(keys: &[&Pubkey]) -> ProgramResult {
    for (i, key) in keys.iter().enumerate() {
        require(!keys[..i].contains(key), ProgramError::InvalidArgument)?;
    }
    Ok(())
}

fn program(account: &AccountInfo, id: &Pubkey) -> ProgramResult {
    require(
        account.key == id && account.executable,
        ProgramError::IncorrectProgramId,
    )
}

fn mint(account: &AccountInfo) -> Result<Mint, ProgramError> {
    require(
        account.owner == &spl_token::id(),
        ProgramError::IncorrectProgramId,
    )?;
    require(
        account.key != &spl_token::native_mint::id(),
        ProgramError::InvalidArgument,
    )?;
    Mint::unpack(&account.try_borrow_data()?)
}

fn token(
    account: &AccountInfo,
    owner: &Pubkey,
    mint: &Pubkey,
    vault: bool,
) -> Result<TokenAccount, ProgramError> {
    require(
        account.owner == &spl_token::id(),
        ProgramError::IncorrectProgramId,
    )?;
    require(
        account.key
            == &spl_associated_token_account_client::address::get_associated_token_address_with_program_id(
                owner,
                mint,
                &spl_token::id(),
            ),
        ProgramError::InvalidSeeds,
    )?;
    let state = TokenAccount::unpack(&account.try_borrow_data()?)?;
    require(
        state.owner == *owner
            && state.mint == *mint
            && state.state == AccountState::Initialized
            && state.is_native == COption::None,
        ProgramError::InvalidAccountData,
    )?;
    if vault {
        require(
            state.delegate == COption::None && state.close_authority == COption::None,
            ProgramError::InvalidAccountData,
        )?;
    }
    Ok(state)
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.first() {
        Some(0) => authorize(program_id, accounts, data),
        Some(1) if data.len() == 1 => reclaim(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn authorize(program_id: &Pubkey, a: &[AccountInfo], data: &[u8]) -> ProgramResult {
    require(
        data.len() == 67 && data[1] == 1 && data[2] == 0 && data[3..11] == [0; 8],
        ProgramError::InvalidInstructionData,
    )?;
    let [payer, server, payment, asset, source, vault, funder, system, tokens, ata] = a else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(payer)?;
    signer(funder)?;
    for account in [payer, payment, source, vault, funder] {
        writable(account)?;
    }
    program(system, &system_program::id())?;
    program(tokens, &spl_token::id())?;
    program(ata, &spl_associated_token_account_client::program::id())?;
    distinct(&[
        payer.key,
        server.key,
        payment.key,
        asset.key,
        source.key,
        vault.key,
    ])?;
    let salt: [u8; 32] = data[11..43].try_into().unwrap();
    let maximum = u64::from_le_bytes(data[43..51].try_into().unwrap());
    let dc = i64::from_le_bytes(data[51..59].try_into().unwrap());
    let dr = i64::from_le_bytes(data[59..67].try_into().unwrap());
    let now = Clock::get()?.unix_timestamp;
    require(
        maximum > 0 && dc > 0 && now < dc && dc <= dr,
        ProgramError::InvalidArgument,
    )?;
    let (address, bump) = payment_address(program_id, payer.key, &salt);
    require(payment.key == &address, ProgramError::InvalidSeeds)?;
    // Only an unused system-owned, zero-data address may be initialized.
    require(
        payment.owner == &system_program::id() && payment.data_is_empty() && !payment.executable,
        ProgramError::AccountAlreadyInitialized,
    )?;
    let asset_state = mint(asset)?;
    let before_source = token(source, payer.key, asset.key, false)?.amount;
    require(
        vault.key
            == &spl_associated_token_account_client::address::get_associated_token_address_with_program_id(
                payment.key,
                asset.key,
                &spl_token::id(),
            ),
        ProgramError::InvalidSeeds,
    )?;

    let bump_seed = [bump];
    let seeds = [SEED, payer.key.as_ref(), &salt, &bump_seed];
    // allocate+assign handles unsolicited lamports, unlike create_account.
    let rent = Rent::get()?.minimum_balance(PAYMENT_LEN);
    let top_up = rent.saturating_sub(payment.lamports());
    if top_up > 0 {
        invoke(
            &system_instruction::transfer(funder.key, payment.key, top_up),
            &[funder.clone(), payment.clone(), system.clone()],
        )?;
    }
    invoke_signed(
        &system_instruction::allocate(payment.key, PAYMENT_LEN as u64),
        &[payment.clone(), system.clone()],
        &[&seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(payment.key, program_id),
        &[payment.clone(), system.clone()],
        &[&seeds],
    )?;
    invoke(
        &spl_associated_token_account_client::instruction::create_associated_token_account_idempotent(
            funder.key,
            payment.key,
            asset.key,
            &spl_token::id(),
        ),
        &[
            funder.clone(),
            vault.clone(),
            payment.clone(),
            asset.clone(),
            system.clone(),
            tokens.clone(),
            ata.clone(),
        ],
    )?;
    let before_vault = token(vault, payment.key, asset.key, true)?.amount;
    let expected_source = before_source
        .checked_sub(maximum)
        .ok_or(ProgramError::InsufficientFunds)?;
    let expected_vault = before_vault
        .checked_add(maximum)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    invoke(
        &spl_token::instruction::transfer_checked(
            &spl_token::id(),
            source.key,
            asset.key,
            vault.key,
            payer.key,
            &[],
            maximum,
            asset_state.decimals,
        )?,
        &[
            source.clone(),
            asset.clone(),
            vault.clone(),
            payer.clone(),
            tokens.clone(),
        ],
    )?;
    require(
        token(source, payer.key, asset.key, false)?.amount == expected_source
            && token(vault, payment.key, asset.key, true)?.amount == expected_vault,
        ProgramError::InvalidAccountData,
    )?;
    let state = Payment {
        payer: *payer.key,
        server: *server.key,
        mint: *asset.key,
        salt,
        maximum,
        capture_deadline: dc,
        refund_deadline: dr,
        held: maximum,
        refundable: 0,
    };
    payment
        .try_borrow_mut_data()?
        .copy_from_slice(&state.encode());
    Ok(())
}

/// Wire: [1]. Accounts: payer(s), payment(w), mint, vault(w), payer ATA(w), classic Token.
/// Missing payer ATA repair is an explicitly signed preceding ATA instruction in the same tx.
fn reclaim(program_id: &Pubkey, a: &[AccountInfo]) -> ProgramResult {
    let [payer, payment, asset, vault, destination, tokens] = a else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(payer)?;
    for account in [payment, vault, destination] {
        writable(account)?;
    }
    program(tokens, &spl_token::id())?;
    require(
        payment.owner == program_id,
        ProgramError::IncorrectProgramId,
    )?;
    let mut state = Payment::decode(&payment.try_borrow_data()?)?;
    require(
        payer.key == &state.payer && asset.key == &state.mint,
        ProgramError::InvalidArgument,
    )?;
    let (address, bump) = payment_address(program_id, &state.payer, &state.salt);
    require(payment.key == &address, ProgramError::InvalidSeeds)?;
    distinct(&[
        payer.key,
        payment.key,
        asset.key,
        vault.key,
        destination.key,
    ])?;
    require(
        Clock::get()?.unix_timestamp >= state.capture_deadline && state.held > 0,
        ProgramError::InvalidArgument,
    )?;
    let asset_state = mint(asset)?;
    let before_vault = token(vault, payment.key, asset.key, true)?.amount;
    let before_destination = token(destination, payer.key, asset.key, false)?.amount;
    let expected_vault = before_vault
        .checked_sub(state.held)
        .ok_or(ProgramError::InsufficientFunds)?;
    let expected_destination = before_destination
        .checked_add(state.held)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let bump_seed = [bump];
    let seeds = [SEED, state.payer.as_ref(), &state.salt, &bump_seed];
    invoke_signed(
        &spl_token::instruction::transfer_checked(
            &spl_token::id(),
            vault.key,
            asset.key,
            destination.key,
            payment.key,
            &[],
            state.held,
            asset_state.decimals,
        )?,
        &[
            vault.clone(),
            asset.clone(),
            destination.clone(),
            payment.clone(),
            tokens.clone(),
        ],
        &[&seeds],
    )?;
    require(
        token(vault, payment.key, asset.key, true)?.amount == expected_vault
            && token(destination, payer.key, asset.key, false)?.amount == expected_destination,
        ProgramError::InvalidAccountData,
    )?;
    state.held = 0;
    payment
        .try_borrow_mut_data()?
        .copy_from_slice(&state.encode());
    Ok(())
}
