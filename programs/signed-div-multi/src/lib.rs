//! Several signed divisions per function.
//!
//! The linker computes register liveness once per function, then rewrites
//! every signed `div`/`mod` into an unsigned division with sign fix-ups using
//! scratch registers that are dead at that division (spilling live ones when
//! none are free). Each operation below stresses that liveness across
//! straight-line code, branches and loop back edges, under enough register
//! pressure that at least one rewrite spills. Mirrors
//! `tests/assembly/signed_div_multi.rs` in sbpf-linker.
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

pub const OP_TWO_DIVS: u8 = 0;
pub const OP_CHAINED_DIVS: u8 = 1;
pub const OP_DIV_IN_LOOP: u8 = 2;
pub const OP_DIV_LIVE_ACROSS_BACK_EDGE: u8 = 3;
pub const OP_DIVS_IN_BRANCHES: u8 = 4;
pub const OP_VALUE_DEFINED_BETWEEN: u8 = 5;
pub const OP_COUNT: u8 = 6;

/// Number of `i64` arguments every operation can read.
pub const ARGS: usize = 12;

fn rd(input: *const i64, i: usize) -> i64 {
    unsafe { read_volatile(input.add(i)) }
}

/// Two independent divisions in one block, six values live across both.
#[inline(never)]
fn two_divs(input: *const i64) -> u64 {
    let (v0, v1, v2, v3, v4, v5) = (rd(input, 0), rd(input, 1), rd(input, 2), rd(input, 3), rd(input, 4), rd(input, 5));
    let q1 = rd(input, 6).checked_div(rd(input, 7)).unwrap_or(0);
    let q2 = rd(input, 8).checked_div(rd(input, 9)).unwrap_or(0);
    ((((((q1 ^ v0).wrapping_mul(3) ^ v1).wrapping_mul(3) ^ v2).wrapping_mul(3) ^ v3).wrapping_mul(3) ^ v4).wrapping_mul(3) ^ v5 ^ q2) as u64
}

/// The first quotient is the second dividend.
#[inline(never)]
fn chained_divs(input: *const i64) -> u64 {
    let (v0, v1, v2, v3, v4) = (rd(input, 0), rd(input, 1), rd(input, 2), rd(input, 3), rd(input, 4));
    let (a, b, c) = (rd(input, 5), rd(input, 6), rd(input, 7));
    let q1 = a.checked_div(b).unwrap_or(0);
    let q2 = q1.checked_rem(c).unwrap_or(0);
    (((((q2 ^ v0).wrapping_mul(3) ^ v1).wrapping_mul(3) ^ v2).wrapping_mul(3) ^ v3).wrapping_mul(3) ^ v4 ^ q1) as u64
}

/// A division inside a loop; loop-carried and loop-invariant values stay live
/// around the back edge.
#[inline(never)]
fn div_in_loop(input: *const i64) -> u64 {
    let n = rd(input, 0) & 7;
    let (k0, k1, k2, k3, k4) = (rd(input, 1), rd(input, 2), rd(input, 3), rd(input, 4), rd(input, 5));
    let mut acc = rd(input, 6);
    let mut x = rd(input, 7);
    for _ in 0..n {
        acc = acc.checked_div(x).unwrap_or(1) ^ k0;
        x = x.wrapping_mul(k1) ^ k2;
        acc = acc.wrapping_add(k3) ^ k4;
    }
    (acc ^ x) as u64
}

/// `j0`-`j2` are read only before the division inside the loop, so they are
/// live at the division solely through the back edge.
#[inline(never)]
fn div_live_across_back_edge(input: *const i64) -> u64 {
    let n = rd(input, 0) & 7;
    let (j0, j1, j2) = (rd(input, 1), rd(input, 2), rd(input, 3));
    let (k0, k1, k2) = (rd(input, 4), rd(input, 5), rd(input, 6));
    let mut acc = rd(input, 7);
    let x = rd(input, 8);
    for _ in 0..n {
        acc = ((acc ^ j0).wrapping_mul(j1) ^ j2).checked_div(x).unwrap_or(1);
        acc = (acc ^ k0).wrapping_mul(k1) ^ k2;
    }
    acc as u64
}

/// Different signed operations on each side of a branch, with different values
/// live in each arm.
#[inline(never)]
fn divs_in_branches(input: *const i64) -> u64 {
    let (v0, v1, v2, v3, v4) = (rd(input, 0), rd(input, 1), rd(input, 2), rd(input, 3), rd(input, 4));
    let (a, b, c, d) = (rd(input, 5), rd(input, 6), rd(input, 7), rd(input, 8));
    let r = if rd(input, 9) & 1 == 0 {
        (a.checked_div(b).unwrap_or(0) ^ v0).wrapping_mul(v1)
    } else {
        (c.checked_rem(d).unwrap_or(0) ^ v2).wrapping_mul(v3)
    };
    (r ^ v4) as u64
}

/// `w` is defined between the two divisions (its load address depends on the
/// first quotient), so it is live across the second division only.
#[inline(never)]
fn value_defined_between(input: *const i64) -> u64 {
    let (v0, v1, v2, v3, v4) = (rd(input, 0), rd(input, 1), rd(input, 2), rd(input, 3), rd(input, 4));
    let (a, b, c) = (rd(input, 5), rd(input, 6), rd(input, 7));
    let q1 = a.checked_div(b).unwrap_or(0);
    let w = rd(input, 8 + (q1 & 1) as usize);
    let q2 = c.checked_div(w ^ v0).unwrap_or(0);
    ((((q1 ^ v1).wrapping_mul(3) ^ v2).wrapping_mul(3) ^ v3).wrapping_mul(3) ^ v4 ^ q2 ^ w) as u64
}

/// Shared by the program and the host test. `args` must point to `ARGS`
/// readable `i64` values.
pub fn compute(op: u8, args: *const i64) -> u64 {
    match op {
        OP_TWO_DIVS => two_divs(args),
        OP_CHAINED_DIVS => chained_divs(args),
        OP_DIV_IN_LOOP => div_in_loop(args),
        OP_DIV_LIVE_ACROSS_BACK_EDGE => div_live_across_back_edge(args),
        OP_DIVS_IN_BRANCHES => divs_in_branches(args),
        OP_VALUE_DEFINED_BETWEEN => value_defined_between(args),
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

    /// Mixes edge values, small values (so loops run and divisors of 0 and -1
    /// come up) and arbitrary bits.
    fn random_args(rng: &mut u64) -> [i64; ARGS] {
        core::array::from_fn(|_| {
            let r = next(rng);
            match r % 3 {
                0 => EDGES[(r >> 8) as usize % EDGES.len()],
                1 => (r >> 40) as i64 % 64,
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
    fn test_multiple_signed_divs_match_rust_semantics() {
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
