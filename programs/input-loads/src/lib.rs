#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    const SMALL_LEN: usize = 32;
    const LARGE_LEN: usize = 128;

    static SMALL_EXPECTED: [u8; SMALL_LEN] = [3u8; SMALL_LEN];
    static LARGE_EXPECTED: [u8; LARGE_LEN] = [3u8; LARGE_LEN];

    #[inline(never)]
    fn compare_small(input: *const u8) -> bool {
        let actual = unsafe { core::slice::from_raw_parts(input.add(16), SMALL_LEN) };
        let expected = unsafe { core::slice::from_raw_parts(SMALL_EXPECTED.as_ptr(), SMALL_LEN) };
        !actual.ne(expected)
    }

    #[inline(never)]
    fn compare_large(input: *const u8) -> bool {
        let len = core::hint::black_box(LARGE_LEN);
        let actual = unsafe { core::slice::from_raw_parts(input.add(16), len) };
        let expected = unsafe { core::slice::from_raw_parts(LARGE_EXPECTED.as_ptr(), len) };
        !actual.ne(expected)
    }

    #[unsafe(no_mangle)]
    extern "C" fn entrypoint(input: *mut u8) -> u64 {
        let len = unsafe { core::ptr::read_volatile((input as *const u64).add(1)) } as usize;

        let matched = match len {
            SMALL_LEN => compare_small(input),
            LARGE_LEN => compare_large(input),
            _ => return 2,
        };

        if matched {
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
    fn test_input_loads_matching_input_succeeds() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        for len in [32usize, 128] {
            let instruction = Instruction {
                program_id,
                accounts: vec![],
                data: vec![3u8; len],
            };
            let result = mollusk.process_instruction(&instruction, &[]);
            assert_eq!(result.raw_result, Ok(()), "len: {len}");
        }
    }

    #[test]
    fn test_input_loads_corrupted_input_fails() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        for len in [32usize, 128] {
            let mut data = vec![3u8; len];
            data[len / 2] = 4;
            let instruction = Instruction {
                program_id,
                accounts: vec![],
                data,
            };
            let result = mollusk.process_instruction(&instruction, &[]);
            assert!(result.raw_result.is_err(), "len: {len}");
        }
    }

    #[test]
    fn test_input_loads_unexpected_length_fails() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        for len in [0usize, 16, 64, 129] {
            let instruction = Instruction {
                program_id,
                accounts: vec![],
                data: vec![3u8; len],
            };
            let result = mollusk.process_instruction(&instruction, &[]);
            assert!(result.raw_result.is_err(), "len: {len}");
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
        let small = Benchmark::new("bench-input-loads-small").run(
            mollusk,
            &Instruction {
                program_id,
                accounts: vec![],
                data: vec![3u8; 32],
            },
            &[],
        )?;

        let large = Benchmark::new("bench-input-loads-large").run(
            mollusk,
            &Instruction {
                program_id,
                accounts: vec![],
                data: vec![3u8; 128],
            },
            &[],
        )?;

        Ok(vec![small, large])
    }
}
