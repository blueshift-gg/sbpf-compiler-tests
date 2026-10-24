#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]

use pinocchio::{
    ProgramResult, account_info::AccountInfo, no_allocator, nostd_panic_handler,
    program_entrypoint, program_error::ProgramError, pubkey::Pubkey,
};

pub mod constants;
pub mod instructions;
pub mod state;
#[cfg(test)]
mod tests;
pub use instructions::*;
use pinocchio_pubkey::declare_id;

use crate::state::Context;

program_entrypoint!(process_instruction);

no_allocator!();
nostd_panic_handler!();

declare_id!("22222222222222222222222222222222222222222222");

fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (discriminator, context) = instruction_data
        .split_first()
        .map(|(discriminator, instruction_data)| {
            (discriminator, Context::from((accounts, instruction_data)))
        })
        .ok_or(ProgramError::InvalidInstructionData)?;
    match discriminator {
        0 => Make::try_from(context)?.execute(),
        1 => Take::try_from(context)?.execute(),
        2 => Refund::try_from(context)?.execute(),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
