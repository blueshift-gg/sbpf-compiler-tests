//! Signed division and remainder.
//!
//! For BPF v4, LLVM emits signed `div`/`mod` as the unsigned opcodes with
//! `off = 1`. SBPF v0/v3 only has unsigned division, so the linker rewrites
//! each into an unsigned division wrapped in sign fix-ups
//! (blueshift-gg/sbpf-linker#152). Each operation below is one shape of that:
//! 64- and 32-bit, register and constant divisors of either sign.
//!
//! Instruction data: `[op: u64 LE, a: i64 LE, b: i64 LE, expected: u64 LE]`.
//! The program returns 0 if `compute(op, a, b) == expected`, 1 otherwise. On a
//! mismatch it also sets the value it computed as return data (8 bytes LE), so
//! a failing test can show what the program actually produced.

#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

pub const OP_DIV64: u8 = 0;
pub const OP_REM64: u8 = 1;
pub const OP_DIV32: u8 = 2;
pub const OP_REM32: u8 = 3;
pub const OP_WRAPPING_DIV64: u8 = 4;
pub const OP_DIV64_BY_7: u8 = 5;
pub const OP_REM64_BY_7: u8 = 6;
pub const OP_DIV64_BY_NEG3: u8 = 7;
pub const OP_REM64_BY_NEG3: u8 = 8;
pub const OP_DIV32_BY_7: u8 = 9;
pub const OP_DIV32_BY_NEG3: u8 = 10;
pub const OP_REM32_BY_NEG3: u8 = 11;
pub const OP_COUNT: u8 = 12;

/// Shared by the program and the host test, so the host computes the expected
/// value with Rust's signed division semantics.
#[inline(always)]
pub fn compute(op: u8, a: i64, b: i64) -> u64 {
    let (a32, b32) = (a as i32, b as i32);
    match op {
        // The shape from #152: `checked_div` on `i64` values.
        OP_DIV64 => a.checked_div(b).unwrap_or(0) as u64,
        OP_REM64 => a.checked_rem(b).unwrap_or(0) as u64,
        // 32-bit results are sign-extended when widened.
        OP_DIV32 => a32.checked_div(b32).unwrap_or(0) as u64,
        OP_REM32 => a32.checked_rem(b32).unwrap_or(0) as u64,
        // `i64::MIN / -1` wraps to `i64::MIN` instead of being rejected.
        OP_WRAPPING_DIV64 => match b {
            0 => 0,
            _ => a.wrapping_div(b) as u64,
        },
        OP_DIV64_BY_7 => (a / 7) as u64,
        OP_REM64_BY_7 => (a % 7) as u64,
        OP_DIV64_BY_NEG3 => (a / -3) as u64,
        // The remainder takes the dividend's sign, not the divisor's.
        OP_REM64_BY_NEG3 => (a % -3) as u64,
        OP_DIV32_BY_7 => (a32 / 7) as u64,
        OP_DIV32_BY_NEG3 => (a32 / -3) as u64,
        OP_REM32_BY_NEG3 => (a32 % -3) as u64,
        _ => u64::MAX,
    }
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    use {core::ptr::read_unaligned, solana_define_syscall::definitions::sol_set_return_data};

    #[unsafe(no_mangle)]
    extern "C" fn entrypoint(input: *mut u8) -> u64 {
        // With no accounts, instruction data starts at offset 16.
        let data = unsafe { input.add(16) } as *const u64;
        let op = unsafe { read_unaligned(data) } as u8;
        let a = unsafe { read_unaligned(data.add(1)) } as i64;
        let b = unsafe { read_unaligned(data.add(2)) } as i64;
        let expected = unsafe { read_unaligned(data.add(3)) };

        let actual = super::compute(op, a, b);
        if actual == expected {
            0
        } else {
            // Only on mismatch, so the success path (and its CU cost) is unchanged.
            let bytes = actual.to_le_bytes();
            unsafe { sol_set_return_data(bytes.as_ptr(), bytes.len() as u64) };
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        harness::{Instruction, Mollusk, Pubkey},
    };

    /// Sign boundaries for both widths, plus values whose low 32 bits are 0 or
    /// -1 so the 32-bit operations also see zero and `-1` divisors.
    const EDGES: &[i64] = &[
        i64::MIN,
        i64::MIN + 1,
        -7,
        -3,
        -1,
        0,
        1,
        3,
        7,
        i64::MAX,
        i32::MIN as i64,
        i32::MAX as i64,
        1 << 32,
        -(1 << 32) - 1,
    ];

    /// xorshift64*: deterministic pseudo-random inputs without a dependency.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state >> 12;
        *state ^= *state << 25;
        *state ^= *state >> 27;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn cases() -> Vec<(u8, i64, i64)> {
        let mut rng = 0x9e37_79b9_7f4a_7c15;
        let mut cases = Vec::new();
        for op in 0..OP_COUNT {
            for &a in EDGES {
                for &b in EDGES {
                    cases.push((op, a, b));
                }
            }
            for _ in 0..64 {
                cases.push((op, next(&mut rng) as i64, (next(&mut rng) as i64) >> 40));
            }
        }
        cases
    }

    fn instruction_data(op: u8, a: i64, b: i64, expected: u64) -> Vec<u8> {
        [op as u64, a as u64, b as u64, expected]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    #[test]
    fn test_signed_div_matches_rust_semantics() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        let cases = cases();
        let failures: Vec<String> = cases
            .iter()
            .filter_map(|&(op, a, b)| {
                let expected = compute(op, a, b);
                let result = mollusk.process_instruction(
                    &Instruction {
                        program_id,
                        accounts: vec![],
                        data: instruction_data(op, a, b, expected),
                    },
                    &[],
                );
                let actual = <[u8; 8]>::try_from(result.return_data.as_slice())
                    .map(|bytes| format!("{:#x}", u64::from_le_bytes(bytes)))
                    .unwrap_or_else(|_| "?".to_owned());
                result.raw_result.err().map(|err| {
                    format!("op {op} a {a} b {b} expected {expected:#x} actual {actual}: {err:?}")
                })
            })
            .collect();

        assert!(
            failures.is_empty(),
            "{} of {} cases failed:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    }
}
