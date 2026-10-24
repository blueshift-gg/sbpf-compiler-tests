//! 32-bit arithmetic whose result is read as 64 bits.
//!
//! LLVM's BPF backend compiles `u32` arithmetic to ALU32 instructions and relies
//! on eBPF's rule that they zero-extend their result. In SBPF `add32`, `sub32`
//! and `mul32` sign-extend instead, so a 32-bit result with bit 31 set gets
//! `0xFFFFFFFF` in its upper half unless the linker compensates. Each operation
//! below widens a `u32` result to `u64` and hands it to a 64-bit consumer.
//!
//! Instruction data: `[op: u8, a: u32 LE, b: u32 LE, expected: u64 LE]`.
//! The program returns 0 if `compute(op, a, b) == expected`, 1 otherwise. On a
//! mismatch it also sets the value it computed as return data (8 bytes LE), so
//! a failing test can show what the program actually produced.

#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]

#[cfg(target_arch = "bpf")]
use solana_compiler_builtins as _;

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

pub const OP_ADD: u8 = 0;
pub const OP_SUB: u8 = 1;
pub const OP_MUL: u8 = 2;
pub const OP_LOOP_SUB: u8 = 3;
pub const OP_ADD_SHIFT: u8 = 4;
pub const OP_ADD_MASK: u8 = 5;
pub const OP_INDEX: u8 = 6;
pub const OP_CALL_RET: u8 = 7;
pub const OP_CALL_ARG: u8 = 8;
pub const OP_SIGN_EXTEND: u8 = 9;
pub const OP_CHECKED_ADD: u8 = 10;
pub const OP_OVERFLOWING_SUB: u8 = 11;
pub const OP_HASH: u8 = 12;
pub const OP_STRUCT_FIELDS: u8 = 13;
pub const OP_SIGNED_DIV_ADD: u8 = 14;
pub const OP_ALIGN_DOWN_SUB: u8 = 15;

const TABLE: [u64; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];

#[inline(never)]
fn add_u32(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

/// Reads every bit of its argument.
#[inline(never)]
fn mix(x: u64) -> u64 {
    x ^ (x >> 7)
}

/// The low byte of `a` divided by `b` (0 if `b` is 0), plus one as a `u32`. Not
/// inlined, and `b` is opaque, so LLVM keeps a 64-bit signed division: the mask
/// stays a 64-bit `and64` and the quotient goes straight into `add32`.
#[inline(never)]
fn signed_div_add(a: i64, b: i64) -> u64 {
    let quotient = (a & 0xFF)
        .checked_div(core::hint::black_box(b))
        .unwrap_or(0);
    (quotient as u32).wrapping_add(1) as u64
}

/// The byte sum of `x` plus one, rounded down to a multiple of 8, minus one as
/// a `u32`, plus the rounded sum itself. Not inlined, and adding `rounded` back
/// uses all 64 bits of it, so LLVM keeps the mask as `and64 rX, -8` instead of
/// doing the sum and mask in 32 bits.
#[inline(never)]
fn align_down_sub(x: u64) -> u64 {
    let sum = x
        .to_le_bytes()
        .into_iter()
        .fold(1u64, |acc, byte| acc + byte as u64);
    let rounded = sum & !7;
    ((rounded as u32).wrapping_sub(1) as u64).wrapping_add(rounded)
}

#[repr(C)]
struct Fields {
    word: u32,
    wide: u64,
}

/// Shared by the program and the host test, so the host computes the expected
/// value with Rust's zero-extending `u32 as u64` semantics.
#[inline(always)]
pub fn compute(op: u8, a: u32, b: u32) -> u64 {
    match op {
        OP_ADD => a.wrapping_add(b) as u64,
        OP_SUB => a.wrapping_sub(b) as u64,
        OP_MUL => a.wrapping_mul(b) as u64,
        // `a` decremented `b & 7` times in a loop, then widened.
        OP_LOOP_SUB => {
            let mut x = a;
            for _ in 0..(b & 7) {
                x = core::hint::black_box(x).wrapping_sub(1);
            }
            x as u64
        }
        // A widened sum shifted left, so its upper half stays in the result.
        OP_ADD_SHIFT => (a.wrapping_add(b) as u64) << 16,
        // A widened sum masked to 16 bits: the upper half never matters.
        OP_ADD_MASK => (a.wrapping_add(b) as u64) & 0xFFFF,
        // A table index computed from a widened `u32` sum, so the upper half
        // becomes part of a memory address. (sum * 3) >> 30 is at most 11 for a
        // zero-extended sum.
        OP_INDEX => TABLE[((a.wrapping_add(b) as u64 * 3) >> 30) as usize],
        // A `u32` returned by a non-inlined function, widened by the caller.
        OP_CALL_RET => add_u32(a, b) as u64,
        // A widened `u32` passed as a `u64` argument to a non-inlined function.
        OP_CALL_ARG => mix(a.wrapping_sub(b) as u64),
        // Intended sign extension (`as i32 as i64`): must stay sign-extended.
        OP_SIGN_EXTEND => a.wrapping_add(b) as i32 as i64 as u64,
        // `checked_add`, widened when it doesn't overflow.
        OP_CHECKED_ADD => match a.checked_add(b) {
            Some(sum) => sum as u64,
            None => 1 << 40,
        },
        // `overflowing_sub`, with the borrow packed above the widened result.
        OP_OVERFLOWING_SUB => {
            let (diff, borrow) = a.overflowing_sub(b);
            diff as u64 | (borrow as u64) << 32
        }
        // 32-bit FNV-1a over the bytes of `a` and `b`, widened at the end.
        OP_HASH => {
            let mut hash: u32 = 0x811C_9DC5;
            for byte in a.to_le_bytes().into_iter().chain(b.to_le_bytes()) {
                hash = (hash ^ byte as u32).wrapping_mul(0x0100_0193);
            }
            hash as u64
        }
        // One sum stored in a `u32` field and, widened, in a `u64` field.
        OP_STRUCT_FIELDS => {
            let sum = a.wrapping_add(b);
            let fields = core::hint::black_box(Fields {
                word: sum,
                wide: sum as u64,
            });
            fields.wide.wrapping_add(fields.word as u64)
        }
        // A signed division of a value in [0, 255]. A negative `b` still makes
        // the quotient negative, so range analysis must not treat it as unsigned.
        OP_SIGNED_DIV_ADD => signed_div_add(a as i64, b as i32 as i64),
        // A byte sum in [1, 2041] rounded down by `and64 rX, -8`, which can take
        // it to 0, below that range.
        OP_ALIGN_DOWN_SUB => align_down_sub(a as u64 | (b as u64) << 32),
        _ => u64::MAX,
    }
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    use {
        core::ptr::{read_unaligned, read_volatile},
        solana_define_syscall::definitions::sol_set_return_data,
    };

    #[unsafe(no_mangle)]
    extern "C" fn entrypoint(input: *mut u8) -> u64 {
        // With no accounts, instruction data starts at offset 16.
        let data = unsafe { input.add(16) };
        let op = unsafe { read_volatile(data) };
        let a = unsafe { read_unaligned(data.add(1) as *const u32) };
        let b = unsafe { read_unaligned(data.add(5) as *const u32) };
        let expected = unsafe { read_unaligned(data.add(9) as *const u64) };

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

    fn instruction_data(op: u8, a: u32, b: u32, expected: u64) -> Vec<u8> {
        let mut data = vec![op];
        data.extend_from_slice(&a.to_le_bytes());
        data.extend_from_slice(&b.to_le_bytes());
        data.extend_from_slice(&expected.to_le_bytes());
        data
    }

    /// Inputs whose 32-bit result has bit 31 set expose sign extension.
    const CASES: &[(u8, u32, u32)] = &[
        (OP_ADD, 1, 2),
        (OP_ADD, 0x7FFF_FFFF, 1),
        (OP_ADD, 0xFFFF_FFFF, 1),
        (OP_ADD, 0x8000_0000, 0x8000_0000),
        (OP_ADD, 0xFFFF_FFFF, 0xFFFF_FFFF),
        (OP_SUB, 5, 3),
        (OP_SUB, 0, 1),
        (OP_SUB, 3, 5),
        (OP_SUB, 0x8000_0000, 1),
        (OP_MUL, 3, 7),
        (OP_MUL, 0x1_0000, 0x8000),
        (OP_MUL, 0xFFFF_FFFF, 2),
        (OP_MUL, 0x4000_0000, 4),
        (OP_LOOP_SUB, 10, 3),
        (OP_LOOP_SUB, 2, 5),
        (OP_LOOP_SUB, 0, 7),
        (OP_ADD_SHIFT, 0x1234, 0x10),
        (OP_ADD_SHIFT, 0x7FFF_FFFF, 1),
        (OP_ADD_SHIFT, 0xFFFF_0000, 0x1_0000),
        (OP_ADD_MASK, 0x7FFF_FFFF, 1),
        (OP_ADD_MASK, 0xFFFF_FFFF, 0x10),
        (OP_INDEX, 1, 2),
        (OP_INDEX, 0x7FFF_FFFF, 1),
        (OP_INDEX, 0xFFFF_FFF0, 0xF),
        (OP_CALL_RET, 1, 2),
        (OP_CALL_RET, 0x7FFF_FFFF, 1),
        (OP_CALL_RET, 0xFFFF_FFFF, 0xFFFF_FFFF),
        (OP_CALL_ARG, 5, 3),
        (OP_CALL_ARG, 0, 1),
        (OP_CALL_ARG, 0x8000_0000, 1),
        (OP_SIGN_EXTEND, 1, 2),
        (OP_SIGN_EXTEND, 0x7FFF_FFFF, 1),
        (OP_SIGN_EXTEND, 0, 0xFFFF_FFFF),
        (OP_CHECKED_ADD, 1, 2),
        (OP_CHECKED_ADD, 0x7FFF_FFFF, 1),
        (OP_CHECKED_ADD, 0xFFFF_FFFF, 1),
        (OP_OVERFLOWING_SUB, 5, 3),
        (OP_OVERFLOWING_SUB, 0, 1),
        (OP_OVERFLOWING_SUB, 0x8000_0001, 1),
        (OP_HASH, 0, 0),
        (OP_HASH, 0x1234_5678, 0x9ABC_DEF0),
        (OP_HASH, 0xFFFF_FFFF, 0x8000_0000),
        (OP_STRUCT_FIELDS, 1, 2),
        (OP_STRUCT_FIELDS, 0x7FFF_FFFF, 1),
        (OP_STRUCT_FIELDS, 0xFFFF_FFFF, 0xFFFF_FFFF),
        (OP_SIGNED_DIV_ADD, 100, 3),
        (OP_SIGNED_DIV_ADD, 1, 0),
        (OP_SIGNED_DIV_ADD, 100, 0xFFFF_FFFD),
        (OP_SIGNED_DIV_ADD, 0xFF, 0xFFFF_FFFF),
        (OP_ALIGN_DOWN_SUB, 7, 0),
        (OP_ALIGN_DOWN_SUB, 0, 0),
        (OP_ALIGN_DOWN_SUB, 3, 3),
        (OP_ALIGN_DOWN_SUB, 0xFFFF_FFFF, 0xFFFF_FFFF),
    ];

    #[test]
    fn test_alu32_results_are_zero_extended() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        let failures: Vec<String> = CASES
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
                    format!(
                        "op {op} a {a:#x} b {b:#x} expected {expected:#x} actual {actual}: {err:?}"
                    )
                })
            })
            .collect();

        assert!(
            failures.is_empty(),
            "{} of {} cases failed:\n{}",
            failures.len(),
            CASES.len(),
            failures.join("\n")
        );
    }
}
