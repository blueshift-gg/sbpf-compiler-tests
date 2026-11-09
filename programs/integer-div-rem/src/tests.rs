use super::*;
use harness::{Instruction, Mollusk, Pubkey};

// Include both sides of limb boundaries and signed extremes. Reinterpreting
// these as signed integers also exercises negative dividends and divisors.
const EDGES: &[u128] = &[
    0,
    1,
    2,
    3,
    5,
    7,
    17,
    (1 << 31) - 1,
    1 << 31,
    (1 << 32) - 1,
    1 << 32,
    (1 << 32) + 1,
    (1 << 63) - 1,
    1 << 63,
    (1 << 63) + 1,
    (1 << 64) - 1,
    1 << 64,
    (1 << 64) + 1,
    (1 << 95) - 1,
    1 << 95,
    (1 << 96) - 1,
    1 << 96,
    (1 << 96) + 1,
    (1 << 127) - 1,
    1 << 127,
    (1 << 127) + 1,
    u128::MAX - 16,
    u128::MAX - 6,
    u128::MAX - 2,
    u128::MAX - 1,
    u128::MAX,
];

fn next(state: &mut u64) -> u128 {
    let mut word = || {
        *state ^= *state >> 12;
        *state ^= *state << 25;
        *state ^= *state >> 27;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    };
    ((word() as u128) << 64) | word() as u128
}

fn instruction(program_id: Pubkey, op: u64, a: u128, b: u128) -> Instruction {
    let mut data = op.to_le_bytes().to_vec();
    data.extend_from_slice(&a.to_le_bytes());
    data.extend_from_slice(&b.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

fn run(op: u64, reference: impl Fn(u128, u128) -> Option<u128>) {
    let program_id = Pubkey::new_from_array([2; 32]);
    let mollusk = Mollusk::new(&program_id, &harness::program_elf());
    let mut pairs: Vec<_> = EDGES
        .iter()
        .flat_map(|&a| EDGES.iter().map(move |&b| (a, b)))
        .collect();
    let mut state = 0x9e37_79b9_7f4a_7c15;
    for i in 0..256 {
        let a = next(&mut state);
        let bits = next(&mut state);
        // Wide random divisors mostly yield 0 or 1. Include narrow divisors
        // to also exercise long quotients and 128-by-32/64 helper paths.
        let b = match i % 4 {
            0 => bits,
            1 => bits & u64::MAX as u128,
            2 => bits & u32::MAX as u128,
            _ => EDGES[i as usize % EDGES.len()],
        };
        pairs.push((a, b));
        // Explicit negative narrow divisors for the wide signed operations.
        pairs.push((a, (-(1 + (bits & 0x7fff) as i128)) as u128));
    }

    let mut valid = 0;
    let mut invalid = 0;
    for (a, b) in pairs {
        let expected = reference(a, b);
        let result = mollusk.process_instruction(&instruction(program_id, op, a, b), &[]);
        assert_eq!(result.raw_result, Ok(()), "op {op}, a {a:#x}, b {b:#x}");
        let mut bytes = [0u8; 17];
        if let Some(value) = expected {
            valid += 1;
            bytes[0] = 1;
            bytes[1..].copy_from_slice(&value.to_le_bytes());
        } else {
            invalid += 1;
        }
        assert_eq!(
            result.return_data, bytes,
            "op {op}, a {a:#x}, b {b:#x}, expected {expected:?}"
        );
    }
    assert!(
        valid > 0 && invalid > 0,
        "exercise valid arithmetic and checked rejection"
    );
}

#[test]
fn udiv64() {
    run(UDIV64, |a, b| {
        (a as u64).checked_div(b as u64).map(u128::from)
    });
}
#[test]
fn umod64() {
    run(UMOD64, |a, b| {
        (a as u64).checked_rem(b as u64).map(u128::from)
    });
}
#[test]
fn sdiv64() {
    run(SDIV64, |a, b| {
        (a as i64).checked_div(b as i64).map(|v| v as i128 as u128)
    });
}
#[test]
fn smod64() {
    run(SMOD64, |a, b| {
        (a as i64).checked_rem(b as i64).map(|v| v as i128 as u128)
    });
}
#[test]
fn udiv128() {
    run(UDIV128, |a, b| a.checked_div(b));
}
#[test]
fn umod128() {
    run(UMOD128, |a, b| a.checked_rem(b));
}
#[test]
fn sdiv128() {
    run(SDIV128, |a, b| {
        (a as i128).checked_div(b as i128).map(|v| v as u128)
    });
}
#[test]
fn smod128() {
    run(SMOD128, |a, b| {
        (a as i128).checked_rem(b as i128).map(|v| v as u128)
    });
}
