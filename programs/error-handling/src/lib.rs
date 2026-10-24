#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ProgramError {
        Custom(u32),
        InvalidArgument,
        InvalidInstructionData,
        InvalidAccountData,
        AccountDataTooSmall,
        InsufficientFunds,
        IncorrectProgramId,
        MissingRequiredSignature,
        AccountAlreadyInitialized,
        UninitializedAccount,
        NotEnoughAccountKeys,
        AccountBorrowFailed,
        MaxSeedLengthExceeded,
        InvalidSeeds,
        BorshIoError,
        AccountNotRentExempt,
        UnsupportedSysvar,
        IllegalOwner,
        MaxAccountsDataAllocationsExceeded,
        InvalidRealloc,
        MaxInstructionTraceLengthExceeded,
        BuiltinProgramsMustConsumeComputeUnits,
        InvalidAccountOwner,
        ArithmeticOverflow,
        Immutable,
        IncorrectAuthority,
    }

    type ProgramResult = Result<(), ProgramError>;

    impl From<ProgramError> for u64 {
        fn from(error: ProgramError) -> u64 {
            match error {
                ProgramError::Custom(0) => 1 << 32,
                ProgramError::Custom(code) => code as u64,
                ProgramError::InvalidArgument => 2 << 32,
                ProgramError::InvalidInstructionData => 3 << 32,
                ProgramError::InvalidAccountData => 4 << 32,
                ProgramError::AccountDataTooSmall => 5 << 32,
                ProgramError::InsufficientFunds => 6 << 32,
                ProgramError::IncorrectProgramId => 7 << 32,
                ProgramError::MissingRequiredSignature => 8 << 32,
                ProgramError::AccountAlreadyInitialized => 9 << 32,
                ProgramError::UninitializedAccount => 10 << 32,
                ProgramError::NotEnoughAccountKeys => 11 << 32,
                ProgramError::AccountBorrowFailed => 12 << 32,
                ProgramError::MaxSeedLengthExceeded => 13 << 32,
                ProgramError::InvalidSeeds => 14 << 32,
                ProgramError::BorshIoError => 15 << 32,
                ProgramError::AccountNotRentExempt => 16 << 32,
                ProgramError::UnsupportedSysvar => 17 << 32,
                ProgramError::IllegalOwner => 18 << 32,
                ProgramError::MaxAccountsDataAllocationsExceeded => 19 << 32,
                ProgramError::InvalidRealloc => 20 << 32,
                ProgramError::MaxInstructionTraceLengthExceeded => 21 << 32,
                ProgramError::BuiltinProgramsMustConsumeComputeUnits => 22 << 32,
                ProgramError::InvalidAccountOwner => 23 << 32,
                ProgramError::ArithmeticOverflow => 24 << 32,
                ProgramError::Immutable => 25 << 32,
                ProgramError::IncorrectAuthority => 26 << 32,
            }
        }
    }

    const INVALID_INSTRUCTION: ProgramError = ProgramError::Custom(12);

    #[no_mangle]
    pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
        // Serialized input: zero accounts, instruction length, instruction bytes.
        let len = input.add(8).cast::<u64>().read_unaligned() as usize;
        let instruction_data = core::slice::from_raw_parts(input.add(16), len);

        match process_instruction(instruction_data) {
            Ok(()) => 0,
            Err(error) => error.into(),
        }
    }

    #[inline(always)]
    fn process_instruction(instruction_data: &[u8]) -> ProgramResult {
        let [discriminator, instruction_data @ ..] = instruction_data else {
            return Err(INVALID_INSTRUCTION);
        };
        let result = match *discriminator {
            0 => {
                let [option, initialized, rent_exempt, owner, writable, signer, _remaining @ ..] =
                    instruction_data
                else {
                    return Err(INVALID_INSTRUCTION);
                };
                if !matches!(*option, 0 | 1) {
                    Err(INVALID_INSTRUCTION)
                } else if *initialized != 0 {
                    Err(ProgramError::Custom(6))
                } else if *rent_exempt != 1 {
                    Err(ProgramError::Custom(0))
                } else if *owner != 1 {
                    Err(ProgramError::IncorrectProgramId)
                } else if *writable != 1 {
                    Err(ProgramError::InvalidAccountData)
                } else if *signer != 0 {
                    Err(ProgramError::MissingRequiredSignature)
                } else {
                    Ok(())
                }
            }
            discriminator => instruction_error(discriminator),
        };
        result.inspect_err(log_error)
    }

    #[inline(never)]
    fn instruction_error(discriminator: u8) -> ProgramResult {
        match discriminator {
            1..=25 => Err(ProgramError::Custom(discriminator as u32)),
            _ => Err(INVALID_INSTRUCTION),
        }
    }

    fn log_error(_error: &ProgramError) {
        #[cfg(any(target_arch = "bpf", target_arch = "sbf"))]
        unsafe {
            let log: extern "C" fn(*const u8, u64) = core::mem::transmute(0x207559bdu64);
            log(b"program error".as_ptr(), 13);
        }
    }
}

#[cfg(test)]
mod tests {
    use harness::{Instruction, InstructionError, Mollusk, Pubkey};

    #[test]
    fn test_program_result() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());
        let check = |data: &[u8], expected: Result<(), InstructionError>| {
            let instruction = Instruction::new_with_bytes(program_id, data, vec![]);
            let result = mollusk.process_instruction(&instruction, &[]);
            assert_eq!(result.raw_result, expected, "input: {data:?}");
        };

        check(&[], Err(InstructionError::Custom(12)));
        for discriminator in 1..=255 {
            let code = if discriminator <= 25 {
                discriminator as u32
            } else {
                12
            };
            check(&[discriminator], Err(InstructionError::Custom(code)));
        }
        let success = [0, 1, 0, 1, 1, 1, 0];
        for len in 1..success.len() {
            check(&success[..len], Err(InstructionError::Custom(12)));
        }
        check(&success, Ok(()));
        check(&[0, 0, 0, 1, 1, 1, 0], Ok(()));
        for (offset, value, expected) in [
            (1, 2, InstructionError::Custom(12)),
            (2, 1, InstructionError::Custom(6)),
            (3, 0, InstructionError::Custom(0)),
            (4, 0, InstructionError::IncorrectProgramId),
            (5, 0, InstructionError::InvalidAccountData),
            (6, 1, InstructionError::MissingRequiredSignature),
        ] {
            let mut data = success;
            data[offset] = value;
            check(&data, Err(expected));
        }
    }
}

#[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
pub mod benchmark {
    use harness::{Benchmark, BenchmarkError, BenchmarkResult, Instruction, Mollusk, Pubkey};

    pub fn run(
        mollusk: &Mollusk,
        program_id: Pubkey,
    ) -> Result<Vec<BenchmarkResult>, BenchmarkError> {
        let success = Benchmark::new("bench-error-handling-success").run(
            mollusk,
            &Instruction {
                program_id,
                accounts: vec![],
                data: vec![0, 1, 0, 1, 1, 1, 0],
            },
            &[],
        )?;
        let fail = Benchmark::new("bench-error-handling-fail").run(
            mollusk,
            &Instruction {
                program_id,
                accounts: vec![],
                data: vec![255],
            },
            &[],
        )?;

        Ok(vec![success, fail])
    }
}
