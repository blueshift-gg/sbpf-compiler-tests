#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    const CONST_A: [u8; 8] = [0x11, 1, 2, 3, 4, 5, 6, 7];
    const CONST_B: [u8; 8] = [0x22, 1, 2, 3, 4, 5, 6, 7];
    static STATIC_A: [u8; 8] = [0x33, 1, 2, 3, 4, 5, 6, 7];
    static STATIC_B: [u8; 8] = [0x44, 1, 2, 3, 4, 5, 6, 7];

    #[inline(never)]
    fn borrow_const_direct() -> u64 {
        let ptr = CONST_A.as_ptr();
        unsafe { core::ptr::read_volatile(ptr) as u64 }
    }

    #[inline(never)]
    fn borrow_const_match(flag: u8) -> u64 {
        let bytes = if flag == 0 { &CONST_A } else { &CONST_B };
        unsafe { core::ptr::read_volatile(bytes.as_ptr()) as u64 }
    }

    #[inline(never)]
    fn borrow_static_direct() -> u64 {
        let ptr = STATIC_A.as_ptr();
        unsafe { core::ptr::read_volatile(ptr) as u64 }
    }

    #[inline(never)]
    fn borrow_static_match(flag: u8) -> u64 {
        let bytes = if flag == 0 { &STATIC_A } else { &STATIC_B };
        unsafe { core::ptr::read_volatile(bytes.as_ptr()) as u64 }
    }

    #[inline(never)]
    fn by_value_const_match(flag: u8) -> u64 {
        let bytes = if flag == 0 { CONST_A } else { CONST_B };
        unsafe { core::ptr::read_volatile(bytes.as_ptr()) as u64 }
    }

    #[inline(never)]
    fn mixed_match(flag: u8) -> u64 {
        let bytes = if flag == 0 { &STATIC_A } else { &CONST_B };
        unsafe { core::ptr::read_volatile(bytes.as_ptr()) as u64 }
    }

    #[unsafe(no_mangle)]
    extern "C" fn entrypoint(input: *mut u8) -> u64 {
        // Instruction data starts at offset 16.
        let selector = unsafe { core::ptr::read_volatile(input.add(16)) };
        let flag = unsafe { core::ptr::read_volatile(input.add(17)) };

        let (value, expected): (u64, u8) = match selector {
            0 => (borrow_const_direct(), 0x11),
            1 => (
                borrow_const_match(flag),
                if flag == 0 { 0x11 } else { 0x22 },
            ),
            2 => (borrow_static_direct(), 0x33),
            3 => (
                borrow_static_match(flag),
                if flag == 0 { 0x33 } else { 0x44 },
            ),
            4 => (
                by_value_const_match(flag),
                if flag == 0 { 0x11 } else { 0x22 },
            ),
            5 => (mixed_match(flag), if flag == 0 { 0x33 } else { 0x22 }),
            _ => return 2,
        };

        if value == expected as u64 {
            0x0
        } else {
            0x1
        }
    }
}

#[cfg(test)]
mod tests {
    use harness::{Check, Instruction, Mollusk, Pubkey};

    #[test]
    fn test_const_rodata_all_paths() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        for selector in 0..=5u8 {
            for flag in [0u8, 1] {
                mollusk.process_and_validate_instruction(
                    &Instruction {
                        program_id,
                        accounts: vec![],
                        data: vec![selector, flag],
                    },
                    &[],
                    &[Check::success()],
                );
            }
        }
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
            run_case(mollusk, program_id, "bench-const-direct", 0)?,
            run_case(mollusk, program_id, "bench-const-match", 1)?,
            run_case(mollusk, program_id, "bench-static-direct", 2)?,
            run_case(mollusk, program_id, "bench-static-match", 3)?,
            run_case(mollusk, program_id, "bench-by-value-match", 4)?,
            run_case(mollusk, program_id, "bench-mixed-match", 5)?,
        ])
    }
}
