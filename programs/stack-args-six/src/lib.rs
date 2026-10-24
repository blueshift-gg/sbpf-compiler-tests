#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    #[inline(never)]
    extern "C" fn add_six(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
        a + b + c + d + e + f
    }

    #[unsafe(no_mangle)]
    extern "C" fn entrypoint(input: *mut u8) -> u64 {
        let input = unsafe { core::ptr::read_volatile(input.add(16) as *const u64) };

        let a = input;
        let b = input ^ 2;
        let c = input ^ 3;
        let d = input ^ 4;
        let e = input ^ 5;
        let f = input ^ 6;

        let result = add_six(a, b, c, d, e, f);
        let expected = a + b + c + d + e + f;

        if result == expected {
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
    fn test_stack_args_six() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        for input in [0u64, 1, 2, 0xDEAD_BEEF, u64::MAX] {
            let instruction = Instruction {
                program_id,
                accounts: vec![],
                data: input.to_le_bytes().to_vec(),
            };
            let result = mollusk.process_instruction(&instruction, &[]);
            assert_eq!(result.raw_result, Ok(()), "input: {input:#x}");
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
        let result = Benchmark::new("bench-stack-args-six").run(
            mollusk,
            &Instruction {
                program_id,
                accounts: vec![],
                data: 2u64.to_le_bytes().to_vec(),
            },
            &[],
        )?;

        Ok(vec![result])
    }
}
