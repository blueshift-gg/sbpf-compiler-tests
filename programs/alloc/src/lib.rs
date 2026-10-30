#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    extern crate alloc;

    use pinocchio::{AccountView, Address, ProgramResult};

    pinocchio::program_entrypoint!(process_instruction);
    pinocchio::default_allocator!();
    pinocchio::nostd_panic_handler!();

    fn process_instruction(
        _program_id: &Address,
        _accounts: &mut [AccountView],
        data: &[u8],
    ) -> ProgramResult {
        let boxed = alloc::boxed::Box::new(data.len());
        let val = **core::hint::black_box(&boxed);
        if val == data.len() {
            Ok(())
        } else {
            Err(pinocchio::error::ProgramError::Custom(1))
        }
    }
}

#[cfg(test)]
mod tests {
    use harness::{Check, Instruction, Mollusk};

    #[test]
    pub fn test_alloc() {
        let mollusk = Mollusk::new(&[2u8; 32].into(), &harness::program_elf());
        mollusk.process_and_validate_instruction(
            &Instruction {
                program_id: [2u8; 32].into(),
                accounts: vec![],
                data: vec![0xaa, 0xbb, 0xcc],
            },
            &vec![],
            &[Check::success()],
        );
    }
}
