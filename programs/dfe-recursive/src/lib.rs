#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    #[inline(never)]
    fn factorial(n: u64) -> u64 {
        if n <= 1 {
            return 1;
        }
        let sub = factorial(n - 1);
        (unsafe { core::ptr::read_volatile(&sub as *const u64) }).wrapping_mul(n)
    }

    #[inline(never)]
    fn ping(n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let sub = pong(n - 1);
        (unsafe { core::ptr::read_volatile(&sub as *const u64) }).wrapping_add(1)
    }

    #[inline(never)]
    fn pong(n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let sub = ping(n - 1);
        (unsafe { core::ptr::read_volatile(&sub as *const u64) }).wrapping_add(1)
    }

    fn iterative_factorial(n: u64) -> u64 {
        let mut acc = 1u64;
        let mut i = 2u64;
        while i <= n {
            acc = acc.wrapping_mul(i);
            i += 1;
        }
        acc
    }

    #[unsafe(no_mangle)]
    extern "C" fn entrypoint(input: *mut u8) -> u64 {
        // Instruction data starts at offset 16.
        let selector = unsafe { core::ptr::read_volatile(input.add(16)) };
        let n = unsafe { core::ptr::read_volatile(input.add(17)) } as u64;

        let result = match selector {
            0 => factorial(n),
            1 => ping(n),
            _ => return 2,
        };

        let expected = match selector {
            0 => iterative_factorial(n),
            _ => n,
        };

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
    fn test_dfe_self_recursive_factorial() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        for n in [0u8, 1, 5, 10] {
            let instruction = Instruction {
                program_id,
                accounts: vec![],
                data: vec![0, n],
            };
            let result = mollusk.process_instruction(&instruction, &[]);
            assert_eq!(result.raw_result, Ok(()), "n: {n}");
        }
    }

    #[test]
    fn test_dfe_mutual_recursive() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        for n in [0u8, 4, 10] {
            let instruction = Instruction {
                program_id,
                accounts: vec![],
                data: vec![1, n],
            };
            let result = mollusk.process_instruction(&instruction, &[]);
            assert_eq!(result.raw_result, Ok(()), "n: {n}");
        }
    }

    #[test]
    fn test_dfe_unknown_selector_fails() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        let instruction = Instruction {
            program_id,
            accounts: vec![],
            data: vec![9, 0],
        };
        let result = mollusk.process_instruction(&instruction, &[]);
        assert!(result.raw_result.is_err());
    }
}

#[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
pub mod benchmark {
    use harness::{Benchmark, BenchmarkError, BenchmarkResult, Instruction, Mollusk, Pubkey};

    fn run_case(
        mollusk: &Mollusk,
        program_id: Pubkey,
        name: &str,
        selector: u8,
        n: u8,
    ) -> Result<BenchmarkResult, BenchmarkError> {
        Benchmark::new(name).run(
            mollusk,
            &Instruction {
                program_id,
                accounts: vec![],
                data: vec![selector, n],
            },
            &[],
        )
    }

    pub fn run(
        mollusk: &Mollusk,
        program_id: Pubkey,
    ) -> Result<Vec<BenchmarkResult>, BenchmarkError> {
        Ok(vec![
            run_case(mollusk, program_id, "bench-dfe-factorial", 0, 5)?,
            run_case(mollusk, program_id, "bench-dfe-mutual", 1, 4)?,
        ])
    }
}
