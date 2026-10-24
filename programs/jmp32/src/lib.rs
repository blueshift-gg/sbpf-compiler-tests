#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    #[unsafe(no_mangle)]
    extern "C" fn entrypoint(input: *mut u8) -> u64 {
        let value = unsafe { core::ptr::read_volatile(input.add(16) as *const u32) };

        if value == 7u32 {
            0x0
        } else {
            0x1
        }
    }
}

#[cfg(test)]
mod tests {
    use harness::{Instruction, Mollusk, Pubkey};

    #[test]
    fn test_jmp32_equal_input_succeeds() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        let instruction = Instruction {
            program_id,
            accounts: vec![],
            data: 7u32.to_le_bytes().to_vec(),
        };
        let result = mollusk.process_instruction(&instruction, &[]);
        assert_eq!(result.raw_result, Ok(()));
    }

    #[test]
    fn test_jmp32_unequal_inputs_fail() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        for value in [0u32, 6, 8, 0xFFFF_FFFF, 0x0100_0007] {
            let instruction = Instruction {
                program_id,
                accounts: vec![],
                data: value.to_le_bytes().to_vec(),
            };
            let result = mollusk.process_instruction(&instruction, &[]);
            assert!(result.raw_result.is_err(), "value: {value:#x}");
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
        let result = Benchmark::new("bench-jmp32").run(
            mollusk,
            &Instruction {
                program_id,
                accounts: vec![],
                data: 7u32.to_le_bytes().to_vec(),
            },
            &[],
        )?;

        Ok(vec![result])
    }
}
