#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    #[inline(never)]
    fn float_add(a: f64, b: f64) -> f64 {
        a + b
    }

    #[inline(never)]
    fn float_mul(a: f64, b: f64) -> f64 {
        a * b
    }

    /// Overrides `__muldf3` builtin and returns hard-coded 7.0
    #[unsafe(no_mangle)]
    pub extern "C" fn __muldf3(_a: f64, _b: f64) -> f64 {
        7.0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn entrypoint(input: *mut u8) -> u64 {
        let a = unsafe { core::ptr::read_volatile(input.add(16) as *const f64) };
        let b = unsafe { core::ptr::read_volatile(input.add(24) as *const f64) };
        let op = unsafe { core::ptr::read_volatile(input.add(32)) };

        let expected = if op == 0 {
            // 2.25 + 3.25 = 5.5
            5.5f64
        } else {
            // override always returns 7.0
            7.0f64
        };
        let result = if op == 0 {
            float_add(a, b)
        } else {
            float_mul(a, b)
        };

        if result.to_bits() == expected.to_bits() {
            0
        } else {
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use harness::{Instruction, Mollusk, Pubkey};

    fn run(op: u8) {
        let program_id = Pubkey::new_unique();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        let mut data = vec![0u8; 17];
        data[0..8].copy_from_slice(&2.25f64.to_le_bytes());
        data[8..16].copy_from_slice(&3.25f64.to_le_bytes());
        data[16] = op;

        let instruction = Instruction {
            program_id,
            accounts: vec![],
            data,
        };
        let result = mollusk.process_instruction(&instruction, &[]);

        assert_eq!(result.raw_result, Ok(()), "op: {op}");
    }

    #[test]
    fn test_compiler_builtins() {
        run(0);
    }

    #[test]
    fn test_override_compiler_builtins() {
        run(1);
    }
}
