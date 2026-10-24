#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    #[inline(never)]
    fn panic_path(do_panic: u8) -> u64 {
        if do_panic != 0 {
            panic!();
        }
        0
    }

    #[inline(never)]
    fn bounds_check(flag: u8) -> u64 {
        let idx = flag as usize;
        [7u8][idx] as u64
    }

    #[inline(never)]
    fn unwrap_case(flag: u8) -> u64 {
        let maybe = if flag == 0 { Some(1u64) } else { None };
        maybe.unwrap()
    }

    #[inline(never)]
    fn named_call(input: *mut u8) -> u64 {
        unsafe { core::ptr::read_volatile(input) as u64 }
    }

    #[unsafe(no_mangle)]
    extern "C" fn entrypoint(input: *mut u8) -> u64 {
        // Instruction data starts at offset 16.
        let selector = unsafe { core::ptr::read_volatile(input.add(16)) };
        let flag = unsafe { core::ptr::read_volatile(input.add(17)) };

        let value = match selector {
            0 => panic_path(flag),
            1 => bounds_check(flag),
            2 => unwrap_case(flag),
            3 => {
                let v = named_call(input);
                core::hint::black_box(v);
                0
            }
            _ => return 2,
        };
        core::hint::black_box(value);

        0x0
    }
}

#[cfg(test)]
mod tests {
    use harness::{Instruction, Mollusk, Pubkey};

    #[test]
    fn test_panic_text_unlikely_success_paths() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        for selector in 0..=3u8 {
            let instruction = Instruction {
                program_id,
                accounts: vec![],
                data: vec![selector, 0],
            };
            let result = mollusk.process_instruction(&instruction, &[]);
            assert_eq!(result.raw_result, Ok(()), "selector: {selector}");
        }
    }

    #[test]
    fn test_panic_text_unlikely_panic_paths_fail() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        // Selector 0 with flag != 0: explicit `panic!()`.
        // Selector 1 with flag >= 1: array bounds-check panic.
        // Selector 2 with flag != 0: `None.unwrap()` panic.
        for (selector, flag) in [(0u8, 1u8), (1, 1), (1, 7), (2, 1)] {
            let instruction = Instruction {
                program_id,
                accounts: vec![],
                data: vec![selector, flag],
            };
            let result = mollusk.process_instruction(&instruction, &[]);
            assert!(
                result.raw_result.is_err(),
                "selector: {selector}, flag: {flag}"
            );
        }
    }

    #[test]
    fn test_panic_text_unlikely_unknown_selector_fails() {
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
    ) -> Result<BenchmarkResult, BenchmarkError> {
        Benchmark::new(name).run(
            mollusk,
            &Instruction {
                program_id,
                accounts: vec![],
                data: vec![selector, 0],
            },
            &[],
        )
    }

    pub fn run(
        mollusk: &Mollusk,
        program_id: Pubkey,
    ) -> Result<Vec<BenchmarkResult>, BenchmarkError> {
        Ok(vec![
            run_case(mollusk, program_id, "bench-panic-path", 0)?,
            run_case(mollusk, program_id, "bench-bounds-check", 1)?,
            run_case(mollusk, program_id, "bench-unwrap-case", 2)?,
            run_case(mollusk, program_id, "bench-named-call", 3)?,
        ])
    }
}
