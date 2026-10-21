//! Signed division under register pressure.
//!
//! The linker rewrites each signed `div`/`mod` into an unsigned division with
//! sign fix-ups that needs scratch registers (div: 3, mod: 2). Each operation
//! below keeps a different number of values live across its division, so the
//! linker has to spill 0-3 live registers to the stack around the rewrite and
//! restore them afterwards, below any slots LLVM already uses. Mirrors
//! `tests/assembly/signed_div_spill.rs` in sbpf-linker.
//!
//! Instruction data: `[op: u64 LE, expected: u64 LE, args: [i64 LE; ARGS]]`.
//! The program returns 0 if `compute(op, args) == expected`, 1 otherwise. On a
//! mismatch it also sets the value it computed as return data (8 bytes LE), so
//! a failing test can show what the program actually produced.

#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]

#[cfg(target_arch = "bpf")]
use solana_compiler_builtins as _;

use core::ptr::read_volatile;

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

pub const OP_DIV64_LIVE5: u8 = 0;
pub const OP_DIV64_LIVE6: u8 = 1;
pub const OP_DIV64_LIVE7: u8 = 2;
pub const OP_DIV64_LIVE8: u8 = 3;
pub const OP_DIV64_LIVE9: u8 = 4;
pub const OP_REM64_LIVE7: u8 = 5;
pub const OP_REM64_LIVE8: u8 = 6;
pub const OP_DIV32_LIVE8: u8 = 7;
pub const OP_COUNT: u8 = 8;

/// Number of `i64` arguments every operation can read.
pub const ARGS: usize = 12;

/// Defines `$name`, which reads one value per `$v`, then performs a signed
/// `$method` and folds every value into the result afterwards. Each `$v` is
/// therefore live across the division, so the list length sets the register
/// pressure at the division site.
macro_rules! signed_op_with_live_values {
    ($name:ident, $ty:ty, $method:ident, [$($v:ident),*]) => {
        #[inline(never)]
        fn $name(input: *const $ty) -> u64 {
            let mut i = 0;
            $(let $v = unsafe { read_volatile(input.add(i)) }; i += 1;)*
            let a = unsafe { read_volatile(input.add(i)) };
            let b = unsafe { read_volatile(input.add(i + 1)) };
            let mut acc = a.$method(b).unwrap_or(0);
            $(acc = (acc ^ $v).wrapping_mul(3);)*
            acc as u64
        }
    };
}

// The linker spills 0, 1, 2, 2 (below 1 LLVM slot), 2 (below 2 LLVM slots),
// 1, 1 (below 1 LLVM slot) and 3 registers for these, in order.
signed_op_with_live_values!(div64_live5, i64, checked_div, [v0, v1, v2, v3, v4]);
signed_op_with_live_values!(div64_live6, i64, checked_div, [v0, v1, v2, v3, v4, v5]);
signed_op_with_live_values!(div64_live7, i64, checked_div, [v0, v1, v2, v3, v4, v5, v6]);
signed_op_with_live_values!(div64_live8, i64, checked_div, [v0, v1, v2, v3, v4, v5, v6, v7]);
signed_op_with_live_values!(div64_live9, i64, checked_div, [v0, v1, v2, v3, v4, v5, v6, v7, v8]);
signed_op_with_live_values!(rem64_live7, i64, checked_rem, [v0, v1, v2, v3, v4, v5, v6]);
signed_op_with_live_values!(rem64_live8, i64, checked_rem, [v0, v1, v2, v3, v4, v5, v6, v7]);
signed_op_with_live_values!(div32_live8, i32, checked_div, [v0, v1, v2, v3, v4, v5, v6, v7]);

/// Shared by the program and the host test. `args` must point to `ARGS`
/// readable `i64` values.
pub fn compute(op: u8, args: *const i64) -> u64 {
    match op {
        OP_DIV64_LIVE5 => div64_live5(args),
        OP_DIV64_LIVE6 => div64_live6(args),
        OP_DIV64_LIVE7 => div64_live7(args),
        OP_DIV64_LIVE8 => div64_live8(args),
        OP_DIV64_LIVE9 => div64_live9(args),
        OP_REM64_LIVE7 => rem64_live7(args),
        OP_REM64_LIVE8 => rem64_live8(args),
        OP_DIV32_LIVE8 => div32_live8(args.cast()),
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
        let expected = unsafe { read_unaligned(data.add(1)) };

        let actual = super::compute(op, unsafe { data.add(2) }.cast());
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

    const EDGES: &[i64] = &[i64::MIN, i64::MAX, -1, 0, 1, -7, 7, i32::MIN as i64];

    /// xorshift64*: deterministic pseudo-random inputs without a dependency.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state >> 12;
        *state ^= *state << 25;
        *state ^= *state >> 27;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Mixes edge values (also as 32-bit halves for the `i32` operation),
    /// small values and arbitrary bits, so divisors of 0 and -1 and the
    /// `MIN / -1` overflow all come up.
    fn random_args(rng: &mut u64) -> [i64; ARGS] {
        core::array::from_fn(|_| {
            let r = next(rng);
            let edge = |shift: u32| EDGES[(r >> shift) as usize % EDGES.len()];
            match r % 4 {
                0 => edge(8),
                1 => (edge(8) as u32 as i64) | ((edge(16) as u32 as i64) << 32),
                2 => (r >> 40) as i64 % 64,
                _ => r as i64,
            }
        })
    }

    fn instruction_data(op: u8, expected: u64, args: &[i64; ARGS]) -> Vec<u8> {
        [op as u64, expected]
            .into_iter()
            .chain(args.iter().map(|&arg| arg as u64))
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    #[test]
    fn test_signed_div_with_spills_matches_rust_semantics() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        let mut rng = 0x9e37_79b9_7f4a_7c15;
        let cases: Vec<(u8, [i64; ARGS])> = (0..OP_COUNT)
            .flat_map(|op| (0..256).map(move |_| op))
            .map(|op| (op, random_args(&mut rng)))
            .collect();

        let failures: Vec<String> = cases
            .iter()
            .filter_map(|(op, args)| {
                let expected = compute(*op, args.as_ptr());
                let result = mollusk.process_instruction(
                    &Instruction {
                        program_id,
                        accounts: vec![],
                        data: instruction_data(*op, expected, args),
                    },
                    &[],
                );
                let actual = <[u8; 8]>::try_from(result.return_data.as_slice())
                    .map(|bytes| format!("{:#x}", u64::from_le_bytes(bytes)))
                    .unwrap_or_else(|_| "?".to_owned());
                result.raw_result.err().map(|err| {
                    format!("op {op} args {args:?} expected {expected:#x} actual {actual}: {err:?}")
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
