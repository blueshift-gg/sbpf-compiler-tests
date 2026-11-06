//! Runtime coverage for unsigned/signed division and remainder at 64/128 bits.
//!
//! Input: `[op: u64 LE, a: u128 LE, b: u128 LE]` (40 bytes, no accounts).
//! Signed inputs use their two's-complement bit patterns. 64-bit operations
//! consume the low 64 bits of each operand.
//! Return data: `[valid: u8, value: u128 LE]` (17 bytes). Invalid checked
//! arithmetic returns `valid = 0` and a zero value; negative results are
//! sign-extended to 128 bits. Malformed instructions return status 1.

#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]

pub const UDIV64: u64 = 0;
pub const UMOD64: u64 = 1;
pub const SDIV64: u64 = 2;
pub const SMOD64: u64 = 3;
pub const UDIV128: u64 = 4;
pub const UMOD128: u64 = 5;
pub const SDIV128: u64 = 6;
pub const SMOD128: u64 = 7;

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // A panic is a test failure, rather than an unchecked arithmetic result.
    unsafe { solana_define_syscall::definitions::abort() }
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    use super::*;
    use solana_define_syscall::definitions::sol_set_return_data;

    // Keep each operation separate, with operands supplied at runtime, so
    // division/remainder cannot disappear through constant folding or be
    // combined into one quotient/remainder computation.
    macro_rules! operation {
        ($name:ident, $ty:ty, $method:ident, $result:ty) => {
            #[inline(never)]
            fn $name(a: u128, b: u128) -> Option<u128> {
                (a as $ty).$method(b as $ty).map(|v| v as $result as u128)
            }
        };
    }

    operation!(udiv64, u64, checked_div, u128);
    operation!(umod64, u64, checked_rem, u128);
    operation!(sdiv64, i64, checked_div, i128);
    operation!(smod64, i64, checked_rem, i128);
    operation!(udiv128, u128, checked_div, u128);
    operation!(umod128, u128, checked_rem, u128);
    operation!(sdiv128, i128, checked_div, i128);
    operation!(smod128, i128, checked_rem, i128);

    #[unsafe(no_mangle)]
    extern "C" fn entrypoint(input: *mut u8) -> u64 {
        // With no accounts, the serialized input contains account count,
        // instruction length, then instruction bytes.
        let count = unsafe { input.cast::<u64>().read_unaligned() };
        let len = unsafe { input.add(8).cast::<u64>().read_unaligned() };
        if count != 0 || len != 40 {
            return 1;
        }
        let data = unsafe { core::slice::from_raw_parts(input.add(16), 40) };
        let op = u64::from_le_bytes(data[..8].try_into().unwrap());
        let a = u128::from_le_bytes(data[8..24].try_into().unwrap());
        let b = u128::from_le_bytes(data[24..40].try_into().unwrap());
        let result = match op {
            UDIV64 => udiv64(a, b),
            UMOD64 => umod64(a, b),
            SDIV64 => sdiv64(a, b),
            SMOD64 => smod64(a, b),
            UDIV128 => udiv128(a, b),
            UMOD128 => umod128(a, b),
            SDIV128 => sdiv128(a, b),
            SMOD128 => smod128(a, b),
            _ => return 1,
        };
        let mut output = [0u8; 17];
        if let Some(value) = result {
            output[0] = 1;
            output[1..].copy_from_slice(&value.to_le_bytes());
        }
        unsafe { sol_set_return_data(output.as_ptr(), output.len() as u64) };
        0
    }
}

#[cfg(test)]
mod tests;
