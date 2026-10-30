#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

    pinocchio::program_entrypoint!(process_instruction);
    pinocchio::no_allocator!();
    pinocchio::nostd_panic_handler!();

    pub fn process_instruction(
        program_id: &Address,
        accounts: &mut [AccountView],
        data: &[u8],
    ) -> ProgramResult {
        let [counter] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        if !counter.owned_by(program_id) {
            return Err(ProgramError::IncorrectProgramId);
        }

        if !counter.is_writable() {
            return Err(ProgramError::InvalidAccountData);
        }

        let by: [u8; 8] = data
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let mut bytes = counter.try_borrow_mut()?;
        let stored: &mut [u8; 8] = (&mut bytes[..])
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let next = u64::from_le_bytes(*stored)
            .checked_add(u64::from_le_bytes(by))
            .ok_or(ProgramError::ArithmeticOverflow)?;
        *stored = next.to_le_bytes();
        Ok(())
    }
}

#[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
pub mod benchmark {
    use harness::{
        Account, AccountMeta, Benchmark, BenchmarkError, BenchmarkResult, Instruction, Mollusk,
        Pubkey,
    };

    pub fn run(
        mollusk: &Mollusk,
        program_id: Pubkey,
    ) -> Result<Vec<BenchmarkResult>, BenchmarkError> {
        let counter_key: Pubkey = [9u8; 32].into();
        let counter_account = Account {
            lamports: 1_000_000,
            data: 37u64.to_le_bytes().to_vec(),
            owner: program_id,
            ..Default::default()
        };
        let result = Benchmark::new("bench-counter-add").run(
            mollusk,
            &Instruction {
                program_id,
                accounts: vec![AccountMeta::new(counter_key, false)],
                data: 5u64.to_le_bytes().to_vec(),
            },
            &[(counter_key, counter_account)],
        )?;
        Ok(vec![result])
    }
}
